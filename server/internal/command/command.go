// Package command is the server's command line: serving, and administering users. A server built with an
// extension is another binary that runs the same commands, plus its own, through Main with its Program.
package command

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"

	"golang.org/x/term"

	"agentio.sh/server/internal/config"
	"agentio.sh/server/internal/push"
	"agentio.sh/server/internal/server"
	"agentio.sh/server/internal/store"
)

// Program is a server binary: the core server, or the core with an extension.
type Program struct {
	// Name is the binary's name, in usage and errors.
	Name string
	// Config is the extension's configuration, read from the same file and environment as the core's; nil for none.
	Config config.Section
	// Open opens and migrates the database; nil opens the core schema only.
	Open func(path string) (*store.Store, error)
	// Extend returns the extension of a server about to run.
	Extend func(srv *server.Server, cfg *config.Config, st *store.Store, log *slog.Logger) (server.Extension, error)
	// NoPasswords is a program whose accounts have no passwords; its Extend must return an extension with
	// NoPasswords. User add creates accounts without one, and change-pass is not offered.
	NoPasswords bool
	// Commands are more administration commands by name. They run with the configuration loaded and the database open.
	Commands map[string]Command
}

// Command is an administration command.
type Command struct {
	Usage string // its lines in the usage text, each "  NAME cmd ARGS   What it does" (NAME becomes Program.Name)
	Run   func(ctx context.Context, st *store.Store, args []string) error
}

// Main runs the program with the process's arguments and exits.
func Main(p Program) {
	if err := Run(p, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", p.Name, err)
		os.Exit(1)
	}
}

func (p Program) usage() string {
	userAdd := "  NAME user add [--role admin] USER  Add a user (password from prompt or AGENTIO_PASSWORD)\n"
	changePass := "  NAME user change-pass USER         Change a user's password\n"
	if p.NoPasswords {
		userAdd, changePass = "  NAME user add [--role admin] USER  Add a user\n", ""
	}
	var ext strings.Builder
	names := make([]string, 0, len(p.Commands))
	for name := range p.Commands {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		ext.WriteString(p.Commands[name].Usage + "\n")
	}
	return strings.ReplaceAll(`agentio server

Usage:
  NAME [serve] [--config FILE]       Run the server
  NAME user list                     List users
`+userAdd+`  NAME user del USER                 Delete a user
`+changePass+`  NAME user change-role USER ROLE    Set role (admin or user)
`+ext.String()+`  NAME webpush keys                  Generate VAPID keys for browser push
  NAME version                       Print the version

All server settings can be set in the YAML config file or as AGENTIO_* environment variables
(e.g. public-url → AGENTIO_PUBLIC_URL). See docs/self-hosting.md.
`, "NAME", p.Name)
}

// Run runs one command line.
func Run(p Program, args []string) error {
	fs := flag.NewFlagSet(p.Name, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, p.usage()) }
	configFile := fs.String("config", os.Getenv("AGENTIO_CONFIG"), "config file")
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		if err := fs.Parse(args); err != nil {
			return err
		}
		return p.serve(*configFile)
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "serve":
		if err := fs.Parse(rest); err != nil {
			return err
		}
		return p.serve(*configFile)
	case "version":
		fmt.Printf("%s (source revision %s)\n", server.Version, server.Revision)
		return nil
	case "webpush":
		if len(rest) != 1 || rest[0] != "keys" {
			return fmt.Errorf("usage: %s webpush keys", p.Name)
		}
		private, public, err := push.GenerateVAPIDKeys()
		if err != nil {
			return err
		}
		fmt.Printf("webpush-public-key: %s\nwebpush-private-key: %s\n", public, private)
		return nil
	case "help", "-h", "--help":
		fmt.Print(p.usage())
		return nil
	}
	_, extCmd := p.Commands[cmd]
	if cmd != "user" && !extCmd {
		return fmt.Errorf("unknown command %q (see %s help)", cmd, p.Name)
	}
	sub := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgFile := sub.String("config", *configFile, "config file")
	var role *string
	if !extCmd {
		role = sub.String("role", "user", "role for user add")
	}
	// Allow flags anywhere after the command.
	var positional []string
	for len(rest) > 0 {
		if err := sub.Parse(rest); err != nil {
			return err
		}
		if sub.NArg() == 0 {
			break
		}
		positional = append(positional, sub.Arg(0))
		rest = sub.Args()[1:]
	}
	cfg, err := config.Load(*cfgFile, p.Config)
	if err != nil {
		return err
	}
	st, err := p.open(cfg.DatabasePath())
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	if extCmd {
		return p.Commands[cmd].Run(ctx, st, positional)
	}
	return p.user(ctx, st, positional, *role)
}

func (p Program) open(path string) (*store.Store, error) {
	if p.Open != nil {
		return p.Open(path)
	}
	return store.Open(path)
}

func (p Program) serve(configFile string) error {
	cfg, err := config.Load(configFile, p.Config)
	if err != nil {
		return err
	}
	log := newLogger(cfg)
	st, err := p.open(cfg.DatabasePath())
	if err != nil {
		return err
	}
	defer st.Close()
	srv, err := server.New(cfg, st, log)
	if err != nil {
		return err
	}
	if p.Extend != nil {
		ext, err := p.Extend(srv, cfg, st, log)
		if err != nil {
			return err
		}
		if ext.NoPasswords != p.NoPasswords {
			return fmt.Errorf("%s: the program's NoPasswords and its extension's disagree", p.Name)
		}
		srv.Extend(ext)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("starting agentio server", "binary", p.Name, "version", server.Version, "revision", server.Revision)
	return srv.Run(ctx)
}

func newLogger(cfg *config.Config) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

// user runs a user command.
func (p Program) user(ctx context.Context, st *store.Store, args []string, role string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: %s user list|add|del|change-pass|change-role", p.Name)
	}
	switch args[0] {
	case "list":
		return listUsers(ctx, st)
	case "add":
		if len(args) != 2 {
			return fmt.Errorf("usage: %s user add [--role admin] USER", p.Name)
		}
		return p.addUser(ctx, st, args[1], role)
	case "del":
		if len(args) != 2 {
			return fmt.Errorf("usage: %s user del USER", p.Name)
		}
		u, err := st.UserByUsername(ctx, args[1])
		if err != nil {
			return fmt.Errorf("user %s: %w", args[1], err)
		}
		if err := st.DeleteUser(ctx, u.ID); err != nil {
			return err
		}
		fmt.Printf("user %s removed\n", args[1])
		return nil
	case "change-pass":
		if p.NoPasswords {
			return fmt.Errorf("accounts on %s have no passwords", p.Name)
		}
		if len(args) != 2 {
			return fmt.Errorf("usage: %s user change-pass USER", p.Name)
		}
		u, err := st.UserByUsername(ctx, args[1])
		if err != nil {
			return fmt.Errorf("user %s: %w", args[1], err)
		}
		password, err := readPassword()
		if err != nil {
			return err
		}
		hash, err := server.HashPassword(password)
		if err != nil {
			return err
		}
		if err := st.SetPassword(ctx, u.ID, hash); err != nil {
			return err
		}
		fmt.Printf("changed password for %s\n", args[1])
		return nil
	case "change-role":
		if len(args) != 3 || (args[2] != store.RoleAdmin && args[2] != store.RoleUser) {
			return fmt.Errorf("usage: %s user change-role USER admin|user", p.Name)
		}
		u, err := st.UserByUsername(ctx, args[1])
		if err != nil {
			return fmt.Errorf("user %s: %w", args[1], err)
		}
		return st.SetRole(ctx, u.ID, args[2])
	}
	return fmt.Errorf("unknown user command %q", args[0])
}

func listUsers(ctx context.Context, st *store.Store) error {
	users, err := st.Users(ctx)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "USER\tROLE")
	for _, u := range users {
		fmt.Fprintf(w, "%s\t%s\n", u.Username, u.Role)
	}
	return w.Flush()
}

func (p Program) addUser(ctx context.Context, st *store.Store, name, role string) error {
	if role != store.RoleAdmin && role != store.RoleUser {
		return errors.New("role must be admin or user")
	}
	password := ""
	if !p.NoPasswords {
		var err error
		if password, err = readPassword(); err != nil {
			return err
		}
	}
	u, err := server.NewUser(name, password, role)
	if err != nil {
		return err
	}
	if err := st.AddUser(ctx, u); errors.Is(err, store.ErrConflict) {
		return fmt.Errorf("the username %s is taken", name)
	} else if err != nil {
		return err
	}
	fmt.Printf("user %s added with role %s\n", name, role)
	return nil
}

// readPassword reads a password from AGENTIO_PASSWORD, a prompt, or stdin.
func readPassword() (string, error) {
	pw := os.Getenv("AGENTIO_PASSWORD")
	if pw == "" {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil && line == "" {
				return "", errors.New("no password given (set AGENTIO_PASSWORD or pipe it on stdin)")
			}
			pw = strings.TrimRight(line, "\r\n")
		} else {
			fmt.Fprint(os.Stderr, "password: ")
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return "", err
			}
			fmt.Fprint(os.Stderr, "confirm: ")
			c, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return "", err
			}
			if string(b) != string(c) {
				return "", errors.New("passwords don't match")
			}
			pw = string(b)
		}
	}
	if pw == "" {
		return "", errors.New("no password given")
	}
	return pw, nil
}
