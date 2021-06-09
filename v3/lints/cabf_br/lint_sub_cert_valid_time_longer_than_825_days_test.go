package cabf_br

/*
 * ZLint Copyright 2021 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
	"testing"

	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/test"
)

func TestSubCertValidTimeLongerThan825Days(t *testing.T) {
	inputPath := "subCertOver825DaysBad.pem"
	expected := lint.Error
	out := test.TestLint("e_sub_cert_valid_time_longer_than_825_days", inputPath)
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}

func TestSubCertValidTimeLongerThan825DaysBeforeCutoff(t *testing.T) {
	inputPath := "subCertOver825DaysOK.pem"
	expected := lint.NE
	out := test.TestLint("e_sub_cert_valid_time_longer_than_825_days", inputPath)
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}

func TestSubCertValidTime825Days(t *testing.T) {
	inputPath := "subCert825DaysOK.pem"
	expected := lint.Pass
	out := test.TestLint("e_sub_cert_valid_time_longer_than_825_days", inputPath)
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}

func TestSubCertValidTimeExactly825DaysInclusive(t *testing.T) {
	// This certificate has a notBefore of XXX and a notAfter of YYY, giving it
	// a validity period (calculated inclusive of both endpoints, as per RFC5280)
	// of exactly 825 days (71280000 seconds).
	inputPath := "subCertExactly825DaysInclusive.pem"
	expected := lint.Pass
	out := test.TestLint("e_sub_cert_valid_time_longer_than_825_days", inputPath)
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}

func TestSubCertValidTimeExactly825DaysExclusive(t *testing.T) {
	// This certificate has a notBefore of XXX and a notAfter of YYY, giving it
	// a validity period (calculated inclusive of both endpoints, as per RFC5280)
	// of exactly 825 days and one second (71280001 seconds).
	inputPath := "subCertExactly825DaysExclusive.pem"
	expected := lint.Error
	out := test.TestLint("e_sub_cert_valid_time_longer_than_825_days", inputPath)
	if out.Status != expected {
		t.Errorf("%s: expected %s, got %s", inputPath, expected, out.Status)
	}
}
