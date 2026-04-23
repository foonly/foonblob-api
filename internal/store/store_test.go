package store

import (
	"context"
	"testing"
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
		err = s.CreateIdentity(ctx, id, secret, "http://localhost")
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

		if err := s1.CreateIdentity(ctx, id, secret, ""); err != nil {
			t.Fatalf("failed to create identity in s1: %v", err)
		}

		// We can't easily swap keys in the same memory DB since they are separate stores,
		// but we can simulate a restart with a different key by reading the same DSN if it were a file.
		// For :memory: we just test that GetIdentity returns the encrypted string if decryption fails.

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

		ident, err := s2.GetIdentity(ctx, "bad-id")
		if err != nil {
			t.Fatalf("GetIdentity failed: %v", err)
		}

		if ident.SigningSecret != "enc:invalidbase64" {
			t.Errorf("expected raw encrypted string on decryption failure, got %q", ident.SigningSecret)
		}
	})

	t.Run("BackwardCompatibilityNoEncryption", func(t *testing.T) {
		// Store without encryption key
		s, err := NewSQLiteStore(":memory:", 10, "")
		if err != nil {
			t.Fatalf("failed to create store: %v", err)
		}
		defer s.Close()

		if err := s.CreateIdentity(ctx, id, secret, ""); err != nil {
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
