package dlp

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
)

// GenerateSSN produces a valid US Social Security Number meeting SSA rules.
func GenerateSSN(r *rand.Rand, formatted bool) string {
	var area int
	for {
		area = 1 + r.Intn(899)
		if area != 666 {
			break
		}
	}
	group := 1 + r.Intn(99)
	serial := 1 + r.Intn(9999)

	if formatted {
		return fmt.Sprintf("%03d-%02d-%04d", area, group, serial)
	}
	return fmt.Sprintf("%03d%02d%04d", area, group, serial)
}

// ValidateSSN tests a string against US SSA rules.
func ValidateSSN(ssn string) bool {
	clean := strings.ReplaceAll(strings.ReplaceAll(ssn, "-", ""), " ", "")
	if len(clean) != 9 {
		return false
	}
	for _, c := range clean {
		if c < '0' || c > '9' {
			return false
		}
	}
	area, _ := strconv.Atoi(clean[0:3])
	group, _ := strconv.Atoi(clean[3:5])
	serial, _ := strconv.Atoi(clean[5:9])

	if area == 0 || area == 666 || (area >= 900 && area <= 999) {
		return false
	}
	if group == 0 || serial == 0 {
		return false
	}
	return true
}

// GenerateNINO produces a valid UK National Insurance Number.
func GenerateNINO(r *rand.Rand) string {
	const firstLetters = "ABCEGHJKLMNOPRSTWXYZ"
	const secondLetters = "ABCEGHJKLMNPRSTWXYZ"
	const suffixes = "ABCD"

	f := firstLetters[r.Intn(len(firstLetters))]
	s := secondLetters[r.Intn(len(secondLetters))]
	digits := fmt.Sprintf("%06d", r.Intn(1000000))
	suf := suffixes[r.Intn(len(suffixes))]

	return fmt.Sprintf("%c%c%s%c", f, s, digits, suf)
}

// ValidateNINO validates UK NINO format and invalid prefix/suffix restrictions.
func ValidateNINO(nino string) bool {
	clean := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(nino, "-", ""), " ", ""))
	if len(clean) != 9 {
		return false
	}
	invalidPrefix := "DFIQUV"
	if strings.ContainsRune(invalidPrefix, rune(clean[0])) {
		return false
	}
	invalidSecond := "DFIOQUV"
	if strings.ContainsRune(invalidSecond, rune(clean[1])) {
		return false
	}
	for _, c := range clean[2:8] {
		if c < '0' || c > '9' {
			return false
		}
	}
	last := clean[8]
	return last == 'A' || last == 'B' || last == 'C' || last == 'D' || last == ' '
}

// GenerateSIN produces a valid 9-digit Canadian SIN passing Luhn Mod-10.
func GenerateSIN(r *rand.Rand, formatted bool) string {
	validFirst := []int{1, 2, 3, 4, 5, 6, 7, 9}
	first := validFirst[r.Intn(len(validFirst))]

	var sb strings.Builder
	sb.WriteByte(byte('0' + first))
	for i := 0; i < 7; i++ {
		sb.WriteByte(byte('0' + r.Intn(10)))
	}
	chk, _ := GenerateLuhnCheckDigit(sb.String())
	sb.WriteByte(byte('0' + chk))
	raw := sb.String()

	if formatted {
		return fmt.Sprintf("%s-%s-%s", raw[0:3], raw[3:6], raw[6:9])
	}
	return raw
}

// ValidateSIN validates a Canadian SIN.
func ValidateSIN(sin string) bool {
	clean := strings.ReplaceAll(strings.ReplaceAll(sin, "-", ""), " ", "")
	if len(clean) != 9 {
		return false
	}
	first := clean[0] - '0'
	if first == 0 || first == 8 {
		return false
	}
	return ValidateLuhn(clean)
}
