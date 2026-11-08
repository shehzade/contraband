package dlp

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

type CardBrand string

const (
	BrandVisa       CardBrand = "visa"
	BrandMasterCard CardBrand = "mastercard"
	BrandAmex       CardBrand = "amex"
	BrandDiscover   CardBrand = "discover"
	BrandDiners     CardBrand = "diners"
	BrandJCB        CardBrand = "jcb"
)

type FormatStyle string

const (
	FormatRaw            FormatStyle = "raw"
	FormatHyphenated     FormatStyle = "hyphenated"
	FormatSpaceDelimited FormatStyle = "space"
)

type CreditCard struct {
	Brand          CardBrand `json:"brand"`
	Number         string    `json:"number"`
	Formatted      string    `json:"formatted"`
	ExpMonth       int       `json:"exp_month"`
	ExpYear        int       `json:"exp_year"`
	CVV            string    `json:"cvv"`
	CardholderName string    `json:"cardholder_name"`
}

// ValidateLuhn validates any numeric string against Luhn mod-10.
func ValidateLuhn(number string) bool {
	var digits []int
	for _, r := range number {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		} else if r == ' ' || r == '-' {
			continue
		} else {
			return false
		}
	}
	if len(digits) < 2 {
		return false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// GenerateLuhnCheckDigit computes the single check digit for a given prefix.
func GenerateLuhnCheckDigit(prefix string) (int, error) {
	var digits []int
	for _, r := range prefix {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		} else {
			return 0, fmt.Errorf("invalid character in card prefix: %c", r)
		}
	}
	sum := 0
	alt := true
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return (10 - (sum % 10)) % 10, nil
}

// GenerateCreditCard generates a fully valid CreditCard struct.
func GenerateCreditCard(brand CardBrand, r *rand.Rand, style FormatStyle) (CreditCard, error) {
	var prefix string
	var length int

	switch brand {
	case BrandVisa:
		prefix = "4"
		length = 16
	case BrandMasterCard:
		if r.Intn(2) == 0 {
			prefix = strconv.Itoa(51 + r.Intn(5)) // 51-55
		} else {
			prefix = strconv.Itoa(2221 + r.Intn(500)) // 2221-2720
		}
		length = 16
	case BrandAmex:
		if r.Intn(2) == 0 {
			prefix = "34"
		} else {
			prefix = "37"
		}
		length = 15
	case BrandDiscover:
		if r.Intn(2) == 0 {
			prefix = "6011"
		} else {
			prefix = "65"
		}
		length = 16
	case BrandDiners:
		opt := r.Intn(3)
		if opt == 0 {
			prefix = strconv.Itoa(300 + r.Intn(6)) // 300-305
		} else if opt == 1 {
			prefix = "36"
		} else {
			prefix = "38"
		}
		length = 14
	case BrandJCB:
		prefix = strconv.Itoa(3528 + r.Intn(62)) // 3528-3589
		length = 16
	default:
		return CreditCard{}, fmt.Errorf("unsupported card brand: %s", brand)
	}

	needed := length - len(prefix) - 1
	var sb strings.Builder
	sb.WriteString(prefix)
	for i := 0; i < needed; i++ {
		sb.WriteByte(byte('0' + r.Intn(10)))
	}
	chk, err := GenerateLuhnCheckDigit(sb.String())
	if err != nil {
		return CreditCard{}, err
	}
	sb.WriteByte(byte('0' + chk))
	raw := sb.String()

	// Formatting
	var formatted string
	switch style {
	case FormatRaw:
		formatted = raw
	case FormatHyphenated:
		if length == 14 {
			formatted = fmt.Sprintf("%s-%s-%s", raw[0:4], raw[4:10], raw[10:14])
		} else if length == 15 {
			formatted = fmt.Sprintf("%s-%s-%s", raw[0:4], raw[4:10], raw[10:15])
		} else {
			formatted = fmt.Sprintf("%s-%s-%s-%s", raw[0:4], raw[4:8], raw[8:12], raw[12:16])
		}
	case FormatSpaceDelimited:
		if length == 14 {
			formatted = fmt.Sprintf("%s %s %s", raw[0:4], raw[4:10], raw[10:14])
		} else if length == 15 {
			formatted = fmt.Sprintf("%s %s %s", raw[0:4], raw[4:10], raw[10:15])
		} else {
			formatted = fmt.Sprintf("%s %s %s %s", raw[0:4], raw[4:8], raw[8:12], raw[12:16])
		}
	default:
		formatted = raw
	}

	// CVV & Expiration
	var cvv string
	if brand == BrandAmex {
		cvv = fmt.Sprintf("%04d", r.Intn(10000))
	} else {
		cvv = fmt.Sprintf("%03d", r.Intn(1000))
	}
	now := time.Now()
	expMonth := 1 + r.Intn(12)
	expYear := (now.Year() % 100) + 1 + r.Intn(5) // next 1 to 5 years

	return CreditCard{
		Brand:          brand,
		Number:         raw,
		Formatted:      formatted,
		ExpMonth:       expMonth,
		ExpYear:        expYear,
		CVV:            cvv,
		CardholderName: GenerateRandomName(r),
	}, nil
}

// ValidateCreditCard validates card number format, Luhn Mod-10, and identifies card brand.
func ValidateCreditCard(number string) (CardBrand, bool) {
	if !ValidateLuhn(number) {
		return "", false
	}
	clean := strings.ReplaceAll(strings.ReplaceAll(number, "-", ""), " ", "")
	l := len(clean)
	switch {
	case l == 16 && strings.HasPrefix(clean, "4"):
		return BrandVisa, true
	case l == 16 && (strings.HasPrefix(clean, "51") || strings.HasPrefix(clean, "52") ||
		strings.HasPrefix(clean, "53") || strings.HasPrefix(clean, "54") || strings.HasPrefix(clean, "55") ||
		(len(clean) >= 4 && clean[:4] >= "2221" && clean[:4] <= "2720")):
		return BrandMasterCard, true
	case l == 15 && (strings.HasPrefix(clean, "34") || strings.HasPrefix(clean, "37")):
		return BrandAmex, true
	case l == 16 && (strings.HasPrefix(clean, "6011") || strings.HasPrefix(clean, "65")):
		return BrandDiscover, true
	case l == 14 && (strings.HasPrefix(clean, "36") || strings.HasPrefix(clean, "38") ||
		(len(clean) >= 3 && clean[:3] >= "300" && clean[:3] <= "305")):
		return BrandDiners, true
	case l == 16 && len(clean) >= 4 && clean[:4] >= "3528" && clean[:4] <= "3589":
		return BrandJCB, true
	default:
		return "", false
	}
}
