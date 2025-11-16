//
// Copyright (c) 2025 Markku Rossi
//
// All rights reserved.
//

package tls

import (
	"errors"
	"fmt"
	"io"
	"testing"
)

func TestAlertsAsErrors(t *testing.T) {
	var err error

	err = AlertBadCertificate

	var tlsAlert AlertDescription

	if !errors.As(err, &tlsAlert) {
		t.Errorf("%v is not tls.AlertDescription\n", err)
	}

	err = fmt.Errorf("Certificate validation failed: %w", AlertBadCertificate)
	if !errors.As(err, &tlsAlert) {
		t.Errorf("%v is not tls.AlertDescription\n", err)
	}

	err = fmt.Errorf("write %w failed: %w", AlertDecodeError, io.EOF)
	if !errors.As(err, &tlsAlert) {
		t.Errorf("%v is not tls.AlertDescription\n", err)
	}

	err = fmt.Errorf("write failed: %w: %w", io.EOF, AlertDecryptError)
	if !errors.As(err, &tlsAlert) {
		t.Errorf("%v is not tls.AlertDescription\n", err)
	}

	inner := fmt.Errorf("write %w failed: %w", AlertDecryptError, io.EOF)
	err = fmt.Errorf("failed to decode packet: %w", inner)
	if !errors.As(err, &tlsAlert) {
		t.Errorf("%v is not tls.AlertDescription\n", err)
	}
}
