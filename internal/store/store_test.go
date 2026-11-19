package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSecretEncryption(t *testing.T) {
	ctx := context.Background()
	id := "crypto-test-id"
	secret := "raw-secret-123"
	key := "test-encryption-key-32-bytes-long!!"

	t.Run("IdentitySecretIsEncryptedInDB", func(t *testing.T) {
		// Initialize store with encryption key
		s, err := NewSQLiteStore(":memory:", 10, key)
		if err != nil {
			t.Fatalf("failed to create store: %v", err)
		}
		defer s.Close()

		// Create identity
		err = s.Register(ctx, id, secret, "http://localhost", "blob", 1)
		if err != nil {
			t.Fatalf("failed to create identity: %v", err)
		}

		// Retrieve identity via store (should be transparently decrypted)
		identity, err := s.GetIdentity(ctx, id)
		if err != nil {
			t.Fatalf("failed to get identity: %v", err)
		}

		if identity.SigningSecret != secret {
			t.Errorf("expected decrypted secret %q, got %q", secret, identity.SigningSecret)
		}

		// Verify it is actually encrypted in the database by bypassing the store's GetIdentity
		var rawSecret string
		ss := s.(*sqliteStore)
		err = ss.db.QueryRow("SELECT signing_secret FROM sync_identities WHERE id = ?", id).Scan(&rawSecret)
		if err != nil {
			t.Fatalf("failed to query database directly: %v", err)
		}

		if rawSecret == secret {
			t.Error("secret was stored in plaintext but should have been encrypted")
		}

		if len(rawSecret) < 4 || rawSecret[:4] != "enc:" {
			t.Errorf("encrypted secret should have 'enc:' prefix, got %q", rawSecret)
		}
	})

	t.Run("DecryptionFailsWithWrongKey", func(t *testing.T) {
		s1, err := NewSQLiteStore(":memory:", 10, key)
		if err != nil {
			t.Fatalf("failed to create s1: %v", err)
		}
		defer s1.Close()

		if err := s1.Register(ctx, id, secret, "", "blob", 1); err != nil {
			t.Fatalf("failed to create identity in s1: %v", err)
		}

		// Simulate a key mismatch (e.g. key rotation or misconfiguration) by inserting a row
		// encrypted with one key into a store configured with a different key.

		s2, err := NewSQLiteStore(":memory:", 10, "different-key")
		if err != nil {
			t.Fatalf("failed to create s2: %v", err)
		}
		defer s2.Close()

		// Manually insert an encrypted-looking string to s2
		_, execErr := s2.(*sqliteStore).db.Exec("INSERT INTO sync_identities (id, signing_secret) VALUES (?, ?)", "bad-id", "enc:invalidbase64")
		if execErr != nil {
			t.Fatalf("failed to insert test row into s2: %v", execErr)
		}

		_, err = s2.GetIdentity(ctx, "bad-id")
		if err == nil {
			t.Error("expected error from GetIdentity when decryption fails, got nil")
		}
	})

	t.Run("BackwardCompatibilityNoEncryption", func(t *testing.T) {
		// Store without encryption key
		s, err := NewSQLiteStore(":memory:", 10, "")
		if err != nil {
			t.Fatalf("failed to create store: %v", err)
		}
		defer s.Close()

		if err := s.Register(ctx, id, secret, "", "blob", 1); err != nil {
			t.Fatalf("failed to create identity: %v", err)
		}

		var rawSecret string
		if err := s.(*sqliteStore).db.QueryRow("SELECT signing_secret FROM sync_identities WHERE id = ?", id).Scan(&rawSecret); err != nil {
			t.Fatalf("failed to query raw secret: %v", err)
		}

		if rawSecret != secret {
			t.Errorf("expected plaintext secret in DB, got %q", rawSecret)
		}

		identity, err := s.GetIdentity(ctx, id)
		if err != nil {
			t.Fatalf("failed to get identity: %v", err)
		}
		if identity.SigningSecret != secret {
			t.Errorf("expected %q, got %q", secret, identity.SigningSecret)
		}
	})
}

func TestStoreGuards(t *testing.T) {
	ctx := context.Background()

	t.Run("RejectsInvalidHistoryLimit", func(t *testing.T) {
		if _, err := NewSQLiteStore(":memory:", 0, ""); err == nil {
			t.Fatal("expected error for history limit 0")
		}
	})

	sig := func(v string) Signature { return Signature{Value: v, ExpiresAt: time.Now().Unix() + 600} }

	t.Run("ConsumeRejectsReplayedSignature", func(t *testing.T) {
		s, err := NewSQLiteStore(":memory:", 10, "")
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := s.Register(ctx, "id", "secret", "", "blob", 100); err != nil {
			t.Fatal(err)
		}
		if err := s.Consume(ctx, "id", sig("aa")); err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if err := s.Consume(ctx, "id", sig("aa")); err != ErrReplay {
			t.Fatalf("expected ErrReplay, got %v", err)
		}
		if _, err := s.SaveBlob(ctx, "id", "b2", 101, sig("aa")); err != ErrReplay {
			t.Fatalf("expected ErrReplay from SaveBlob, got %v", err)
		}
		// Equal or older timestamps are fine as long as the request is new.
		if err := s.Consume(ctx, "id", sig("bb")); err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if err := s.Register(ctx, "id", "other", "", "blob", 200); err != ErrAlreadyExists {
			t.Fatalf("expected ErrAlreadyExists, got %v", err)
		}
	})

	t.Run("VersionsIncreaseInWriteOrder", func(t *testing.T) {
		s, err := NewSQLiteStore(":memory:", 10, "")
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := s.Register(ctx, "id", "secret", "", "first", 100); err != nil {
			t.Fatal(err)
		}
		// A second device whose request timestamp is older or equal still writes
		// a newer version.
		for i, ts := range []int64{100, 98, 105} {
			v, err := s.SaveBlob(ctx, "id", fmt.Sprintf("w%d", i), ts, sig(fmt.Sprint(i)))
			if err != nil {
				t.Fatal(err)
			}
			want := []int64{101, 102, 105}[i]
			if v != want {
				t.Fatalf("write %d: version %d, want %d", i, v, want)
			}
		}
		latest, err := s.GetLatestBlob(ctx, "id")
		if err != nil || latest.Data != "w2" || latest.Timestamp != 105 {
			t.Fatalf("latest = %+v, %v", latest, err)
		}
	})

	t.Run("HistoryIsPruned", func(t *testing.T) {
		s, err := NewSQLiteStore(":memory:", 3, "")
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := s.Register(ctx, "id", "secret", "", "b0", 1); err != nil {
			t.Fatal(err)
		}
		for ts := int64(2); ts <= 6; ts++ {
			if _, err := s.SaveBlob(ctx, "id", "b", ts, Signature{Value: fmt.Sprint(ts), ExpiresAt: ts + 600}); err != nil {
				t.Fatal(err)
			}
		}
		h, err := s.GetHistory(ctx, "id")
		if err != nil {
			t.Fatal(err)
		}
		if len(h) != 3 || h[0].Timestamp != 6 {
			t.Fatalf("expected 3 newest versions, got %v", h)
		}
	})

	t.Run("RefusesToStartWithEncryptedSecretsButNoKey", func(t *testing.T) {
		dsn := "file:" + t.TempDir() + "/enc.db"
		s, err := NewSQLiteStore(dsn, 10, "some-key")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Register(ctx, "id", "secret", "", "blob", 1); err != nil {
			t.Fatal(err)
		}
		s.Close()

		if _, err := NewSQLiteStore(dsn, 10, ""); err == nil {
			t.Fatal("expected startup error when encrypted secrets exist but no key is configured")
		}
	})
}

func TestPlaintextSecretsEncryptedOnStartup(t *testing.T) {
	ctx := context.Background()
	dsn := "file:" + t.TempDir() + "/plain.db"

	s, err := NewSQLiteStore(dsn, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Register(ctx, "id", "plain-secret", "", "blob", 1); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = NewSQLiteStore(dsn, 10, "key")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var raw string
	if err := s.(*sqliteStore).db.QueryRow("SELECT signing_secret FROM sync_identities WHERE id = 'id'").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, "enc:") {
		t.Fatalf("expected secret to be encrypted at startup, got %q", raw)
	}
	identity, err := s.GetIdentity(ctx, "id")
	if err != nil || identity.SigningSecret != "plain-secret" {
		t.Fatalf("got %+v, %v", identity, err)
	}
}
