package store

import (
	"context"
	"database/sql"
	"errors"
)

// ErrDeviceElsewhere is returned when a device belongs to another account.
var ErrDeviceElsewhere = errors.New("device belongs to another account")

// ErrDeviceKeys is returned when a device pairs again with keys other than the ones it was recorded with.
var ErrDeviceKeys = errors.New("device keys changed")

// Host is a paired machine: its public keys, never its name.
type Host struct {
	ID      string
	UserID  string
	Key     string
	EncKey  string
	Created int64
}

// Device is a paired browser: its public keys and the origin its sensitive key is bound to, never its name.
type Device struct {
	ID              string
	UserID          string
	Key             string
	SensitiveKey    string
	EncKey          string
	SensitiveOrigin string
	Created         int64
	Hosts           []string // the hosts it is linked with (Devices only)
}

// SameKeys reports whether two records describe the same device keys.
func (d *Device) SameKeys(o *Device) bool {
	return d.Key == o.Key && d.SensitiveKey == o.SensitiveKey && d.EncKey == o.EncKey && d.SensitiveOrigin == o.SensitiveOrigin
}

// WebPush is a device's browser push subscription.
type WebPush struct {
	DeviceID string
	Endpoint string
	Auth     string
	P256dh   string
}

const hostColumns = `id, user_id, key, enc_key, created`

func scanHost(row interface{ Scan(...any) error }) (*Host, error) {
	var h Host
	if err := row.Scan(&h.ID, &h.UserID, &h.Key, &h.EncKey, &h.Created); err != nil {
		return nil, notFound(err)
	}
	return &h, nil
}

// Host returns a host.
func (s *Store) Host(ctx context.Context, id string) (*Host, error) {
	return scanHost(s.QueryRow(ctx, `SELECT `+hostColumns+` FROM hosts WHERE id = ?`, id))
}

// Hosts lists a user's hosts.
func (s *Store) Hosts(ctx context.Context, userID string) ([]*Host, error) {
	rows, err := s.Query(ctx, `SELECT `+hostColumns+` FROM hosts WHERE user_id = ? ORDER BY created, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// DeleteHost removes a user's host, its token and its links, and returns the devices it was linked with.
func (s *Store) DeleteHost(ctx context.Context, userID, id string) ([]string, error) {
	devices, err := s.HostDevices(ctx, id)
	if err != nil {
		return nil, err
	}
	err = s.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM hosts WHERE id = ? AND user_id = ?`, id, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM tokens WHERE kind = ? AND host_id = ?`, TokenHost, id)
		return err
	})
	return devices, err
}

const deviceColumns = `id, user_id, key, sensitive_key, enc_key, sensitive_origin, created`

func scanDevice(row interface{ Scan(...any) error }) (*Device, error) {
	var d Device
	if err := row.Scan(&d.ID, &d.UserID, &d.Key, &d.SensitiveKey, &d.EncKey, &d.SensitiveOrigin, &d.Created); err != nil {
		return nil, notFound(err)
	}
	return &d, nil
}

// Device returns a device.
func (s *Store) Device(ctx context.Context, id string) (*Device, error) {
	return scanDevice(s.QueryRow(ctx, `SELECT `+deviceColumns+` FROM devices WHERE id = ?`, id))
}

// Devices lists a user's devices with the hosts each is linked with.
func (s *Store) Devices(ctx context.Context, userID string) ([]*Device, error) {
	rows, err := s.Query(ctx, `SELECT `+deviceColumns+` FROM devices WHERE user_id = ? ORDER BY created, id`, userID)
	if err != nil {
		return nil, err
	}
	out := []*Device{}
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, d := range out {
		if d.Hosts, err = s.DeviceHosts(ctx, d.ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// DeleteDevice removes a user's device, its links and its push subscription.
func (s *Store) DeleteDevice(ctx context.Context, userID, id string) error {
	res, err := s.Exec(ctx, `DELETE FROM devices WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteLink unlinks a device from one of a user's hosts.
func (s *Store) DeleteLink(ctx context.Context, userID, hostID, deviceID string) error {
	res, err := s.Exec(ctx, `DELETE FROM host_devices WHERE host_id = ? AND device_id = ? AND host_id IN (SELECT id FROM hosts WHERE user_id = ?)`,
		hostID, deviceID, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Linked reports whether a host and a device may relay to each other.
func (s *Store) Linked(ctx context.Context, hostID, deviceID string) (bool, error) {
	var n int
	err := s.QueryRow(ctx, `SELECT COUNT(*) FROM host_devices WHERE host_id = ? AND device_id = ?`, hostID, deviceID).Scan(&n)
	return n > 0, err
}

func (s *Store) ids(ctx context.Context, q string, arg string) ([]string, error) {
	rows, err := s.Query(ctx, q, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// DeviceHosts lists the hosts a device is linked with.
func (s *Store) DeviceHosts(ctx context.Context, deviceID string) ([]string, error) {
	return s.ids(ctx, `SELECT host_id FROM host_devices WHERE device_id = ? ORDER BY host_id`, deviceID)
}

// HostDevices lists the devices a host is linked with.
func (s *Store) HostDevices(ctx context.Context, hostID string) ([]string, error) {
	return s.ids(ctx, `SELECT device_id FROM host_devices WHERE host_id = ? ORDER BY device_id`, hostID)
}

// PairingRecord is everything a confirmed pairing writes.
type PairingRecord struct {
	Host      *Host  // the host; added only with HostToken (a new machine)
	HostToken *Token // the new machine's token
	Device    *Device
}

// CompletePairing records a confirmed pairing in one transaction: the machine when new, the device when
// new to the account, and the link between them. An existing device must belong to the host's account
// (ErrDeviceElsewhere) and keep its keys (ErrDeviceKeys); an existing new machine is ErrConflict.
func (s *Store) CompletePairing(ctx context.Context, r *PairingRecord) error {
	return s.Tx(ctx, func(tx *sql.Tx) error {
		if r.HostToken != nil {
			h := r.Host
			_, err := tx.ExecContext(ctx, `INSERT INTO hosts (`+hostColumns+`) VALUES (?, ?, ?, ?, ?)`, h.ID, h.UserID, h.Key, h.EncKey, h.Created)
			if isUniqueViolation(err) {
				return ErrConflict
			} else if err != nil {
				return err
			}
			if err := s.TxAddToken(ctx, tx, r.HostToken); err != nil {
				return err
			}
		}
		d := r.Device
		existing, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM devices WHERE id = ?`, d.ID))
		switch {
		case errors.Is(err, ErrNotFound):
			if _, err := tx.ExecContext(ctx, `INSERT INTO devices (`+deviceColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				d.ID, r.Host.UserID, d.Key, d.SensitiveKey, d.EncKey, d.SensitiveOrigin, d.Created); err != nil {
				return err
			}
		case err != nil:
			return err
		case existing.UserID != r.Host.UserID:
			return ErrDeviceElsewhere
		case !existing.SameKeys(d):
			return ErrDeviceKeys
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO host_devices (host_id, device_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, r.Host.ID, d.ID)
		return err
	})
}

// SetWebPush stores a device's push subscription, replacing any earlier one.
func (s *Store) SetWebPush(ctx context.Context, w *WebPush) error {
	_, err := s.Exec(ctx, `INSERT INTO webpush (device_id, endpoint, auth, p256dh) VALUES (?, ?, ?, ?)
		ON CONFLICT (device_id) DO UPDATE SET endpoint = excluded.endpoint, auth = excluded.auth, p256dh = excluded.p256dh`,
		w.DeviceID, w.Endpoint, w.Auth, w.P256dh)
	return err
}

// WebPushFor returns a device's push subscription.
func (s *Store) WebPushFor(ctx context.Context, deviceID string) (*WebPush, error) {
	var w WebPush
	err := s.QueryRow(ctx, `SELECT device_id, endpoint, auth, p256dh FROM webpush WHERE device_id = ?`, deviceID).Scan(&w.DeviceID, &w.Endpoint, &w.Auth, &w.P256dh)
	if err != nil {
		return nil, notFound(err)
	}
	return &w, nil
}

// DeleteWebPush removes a device's push subscription. With an endpoint, only if it is still that one, so a
// subscription the browser replaced in the meantime survives a stale push service answer.
func (s *Store) DeleteWebPush(ctx context.Context, deviceID, endpoint string) error {
	if endpoint == "" {
		_, err := s.Exec(ctx, `DELETE FROM webpush WHERE device_id = ?`, deviceID)
		return err
	}
	_, err := s.Exec(ctx, `DELETE FROM webpush WHERE device_id = ? AND endpoint = ?`, deviceID, endpoint)
	return err
}
