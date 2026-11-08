package dlp

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

type ICD10Code struct {
	Code        string `json:"code"`
	Description string `json:"description"`
}

type CPTCode struct {
	Code        string `json:"code"`
	Description string `json:"description"`
}

type Prescription struct {
	Medication string `json:"medication"`
	Dosage     string `json:"dosage"`
	Frequency  string `json:"frequency"`
	Route      string `json:"route"`
}

type MedicalRecord struct {
	MRN           string         `json:"mrn"`
	PatientName   string         `json:"patient_name"`
	DateOfBirth   string         `json:"dob"`
	Gender        string         `json:"gender"`
	SSN           string         `json:"ssn"`
	Address       string         `json:"address"`
	Phone         string         `json:"phone"`
	AttendingMD   string         `json:"attending_physician"`
	PhysicianNPI  string         `json:"physician_npi"`
	PhysicianDEA  string         `json:"physician_dea"`
	Diagnoses     []ICD10Code    `json:"diagnoses"`
	Procedures    []CPTCode      `json:"procedures"`
	Prescriptions []Prescription `json:"prescriptions"`
	EncounterDate string         `json:"encounter_date"`
	FacilityName  string         `json:"facility_name"`
}

var ICD10Dictionary = []ICD10Code{
	{"E11.9", "Type 2 diabetes mellitus without complications"},
	{"I10", "Essential (primary) hypertension"},
	{"J45.909", "Unspecified asthma, uncomplicated"},
	{"F32.9", "Major depressive disorder, single episode, unspecified"},
	{"Z00.00", "Encounter for general adult medical examination without abnormal findings"},
	{"M54.5", "Low back pain"},
	{"K21.9", "Gastro-esophageal reflux disease without esophagitis"},
	{"E78.5", "Hyperlipidemia, unspecified"},
	{"I25.10", "Atherosclerotic heart disease of native coronary artery"},
	{"N18.3", "Chronic kidney disease, stage 3 (moderate)"},
}

var CPTDictionary = []CPTCode{
	{"99213", "Office or other outpatient visit, 20-29 minutes"},
	{"99214", "Office or other outpatient visit, 30-39 minutes"},
	{"80053", "Comprehensive metabolic panel (CMP)"},
	{"85025", "Complete blood count (CBC) with automated differential"},
	{"71046", "Chest X-ray, 2 views"},
	{"93000", "Electrocardiogram, routine ECG with at least 12 leads"},
}

var MedicationDictionary = []Prescription{
	{"Metformin", "500mg", "PO BID", "Oral"},
	{"Lisinopril", "10mg", "PO Daily", "Oral"},
	{"Atorvastatin", "20mg", "PO QPM", "Oral"},
	{"Albuterol", "90mcg", "2 puffs Q4H PRN", "Inhalation"},
	{"Sertraline", "50mg", "PO Daily", "Oral"},
	{"Omeprazole", "20mg", "PO Daily AC", "Oral"},
}

// GenerateNPI generates a valid 10-digit National Provider Identifier.
func GenerateNPI(r *rand.Rand) string {
	// 9 digits prefixed with 1 or 2
	prefix := fmt.Sprintf("%d%08d", 1+r.Intn(2), r.Intn(100000000))
	// Federal standard: calculate check digit using prefix "80840" + 9 digits
	fullStr := "80840" + prefix
	chk, _ := GenerateLuhnCheckDigit(fullStr)
	return fmt.Sprintf("%s%d", prefix, chk)
}

// GenerateDEA generates a valid 9-character US Drug Enforcement Administration registration number.
// Format: 2 alpha characters followed by 7 digits with Mod-10 checksum:
// Sum1 = d1 + d3 + d5, Sum2 = d2 + d4 + d6, CheckDigit = (Sum1 + 2*Sum2) % 10.
func GenerateDEA(r *rand.Rand, lastName string) string {
	firstLetters := []string{"A", "B", "F", "M"}
	c1 := firstLetters[r.Intn(len(firstLetters))]
	c2 := "X"
	trimmed := strings.TrimSpace(lastName)
	for _, ch := range trimmed {
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
			c2 = strings.ToUpper(string(ch))
			break
		}
	}
	d1 := r.Intn(10)
	d2 := r.Intn(10)
	d3 := r.Intn(10)
	d4 := r.Intn(10)
	d5 := r.Intn(10)
	d6 := r.Intn(10)
	sum1 := d1 + d3 + d5
	sum2 := d2 + d4 + d6
	chk := (sum1 + 2*sum2) % 10
	return fmt.Sprintf("%s%s%d%d%d%d%d%d%d", c1, c2, d1, d2, d3, d4, d5, d6, chk)
}

// ValidateDEA verifies that a 9-character DEA number satisfies the US DEA Mod-10 checksum.
func ValidateDEA(dea string) bool {
	if len(dea) != 9 {
		return false
	}
	dea = strings.ToUpper(dea)
	c1 := dea[0]
	if c1 != 'A' && c1 != 'B' && c1 != 'F' && c1 != 'M' && c1 != 'C' && c1 != 'D' && c1 != 'E' && c1 != 'G' && c1 != 'J' && c1 != 'K' && c1 != 'P' && c1 != 'R' && c1 != 'S' && c1 != 'T' && c1 != 'U' && c1 != 'X' {
		return false
	}
	c2 := dea[1]
	if c2 < 'A' || c2 > 'Z' {
		return false
	}
	for i := 2; i < 9; i++ {
		if dea[i] < '0' || dea[i] > '9' {
			return false
		}
	}
	d1 := int(dea[2] - '0')
	d2 := int(dea[3] - '0')
	d3 := int(dea[4] - '0')
	d4 := int(dea[5] - '0')
	d5 := int(dea[6] - '0')
	d6 := int(dea[7] - '0')
	chk := int(dea[8] - '0')
	sum1 := d1 + d3 + d5
	sum2 := d2 + d4 + d6
	return (sum1+2*sum2)%10 == chk
}

// GenerateMedicalRecord creates a fully populated synthetic EHR.
func GenerateMedicalRecord(r *rand.Rand) MedicalRecord {
	year := 1950 + r.Intn(50)
	month := 1 + r.Intn(12)
	day := 1 + r.Intn(28)
	dob := fmt.Sprintf("%04d-%02d-%02d", year, month, day)

	gender := "M"
	if r.Intn(2) == 0 {
		gender = "F"
	}

	encYear := 2024 + r.Intn(3)
	encMonth := 1 + r.Intn(12)
	encDay := 1 + r.Intn(28)
	encDate := fmt.Sprintf("%04d-%02d-%02d", encYear, encMonth, encDay)

	docName := GenerateRandomName(r)
	docParts := strings.Split(docName, " ")
	docLast := docParts[len(docParts)-1]
	attendingMD := "Dr. " + docName + ", MD"
	physicianDEA := GenerateDEA(r, docLast)

	return MedicalRecord{
		MRN:           fmt.Sprintf("MRN-%08d", r.Intn(100000000)),
		PatientName:   GenerateRandomName(r),
		DateOfBirth:   dob,
		Gender:        gender,
		SSN:           GenerateSSN(r, true),
		Address:       GenerateRandomAddress(r),
		Phone:         GenerateRandomPhone(r),
		AttendingMD:   attendingMD,
		PhysicianNPI:  GenerateNPI(r),
		PhysicianDEA:  physicianDEA,
		Diagnoses:     []ICD10Code{ICD10Dictionary[r.Intn(len(ICD10Dictionary))]},
		Procedures:    []CPTCode{CPTDictionary[r.Intn(len(CPTDictionary))]},
		Prescriptions: []Prescription{MedicationDictionary[r.Intn(len(MedicationDictionary))]},
		EncounterDate: encDate,
		FacilityName:  "Metropolitan Medical Center",
	}
}

// FormatHL7v2 produces a valid pipe-delimited HL7 v2.5 message.
func FormatHL7v2(m MedicalRecord) string {
	timestamp := time.Now().Format("20060102150405")
	msh := fmt.Sprintf("MSH|^~\\&|CONTRABAND_EHR|FACILITY_01|EXTERNAL_LISTENER|ARCHIVE|%s||ADT^A08|MSG%s|P|2.5\r\n", timestamp, m.MRN)
	nameParts := strings.Split(m.PatientName, " ")
	lastName := nameParts[len(nameParts)-1]
	firstName := nameParts[0]
	pid := fmt.Sprintf("PID|1||%s^^^MMC^MR||%s^%s||%s|%s|||%s||%s|||S||%s\r\n",
		m.MRN, lastName, firstName, strings.ReplaceAll(m.DateOfBirth, "-", ""), m.Gender, m.Address, m.Phone, m.SSN)
	pv1 := fmt.Sprintf("PV1|1|O|CLINIC_01||||%s^%s|||||||||||||||||||||||||||||||||||||||||||||DEA^%s\r\n", m.PhysicianNPI, m.AttendingMD, m.PhysicianDEA)
	dg1 := fmt.Sprintf("DG1|1||%s^%s^I10|%s|%s|A\r\n", m.Diagnoses[0].Code, m.Diagnoses[0].Description, m.Diagnoses[0].Description, timestamp[:8])
	pr1 := fmt.Sprintf("PR1|1||%s^%s^CPT|%s|%s\r\n", m.Procedures[0].Code, m.Procedures[0].Description, m.Procedures[0].Description, timestamp[:8])
	rxo := fmt.Sprintf("RXO|%s^%s|%s||%s|||||\r\n", m.Prescriptions[0].Medication, m.Prescriptions[0].Medication, m.Prescriptions[0].Dosage, m.Prescriptions[0].Route)

	return msh + pid + pv1 + dg1 + pr1 + rxo
}

// FormatFHIR produces a valid FHIR R4 JSON Bundle.
func FormatFHIR(m MedicalRecord) ([]byte, error) {
	bundle := map[string]any{
		"resourceType": "Bundle",
		"type":         "collection",
		"entry": []map[string]any{
			{
				"resource": map[string]any{
					"resourceType": "Patient",
					"id":           m.MRN,
					"name":         []map[string]any{{"text": m.PatientName}},
					"gender":       strings.ToLower(m.Gender),
					"birthDate":    m.DateOfBirth,
					"telecom":      []map[string]any{{"system": "phone", "value": m.Phone}},
				},
			},
			{
				"resource": map[string]any{
					"resourceType": "Practitioner",
					"id":           m.PhysicianNPI,
					"name":         []map[string]any{{"text": m.AttendingMD}},
					"identifier": []map[string]any{
						{
							"system": "http://hl7.org/fhir/sid/us-npi",
							"value":  m.PhysicianNPI,
						},
						{
							"system": "http://hl7.org/fhir/sid/us-dea",
							"value":  m.PhysicianDEA,
						},
					},
				},
			},
			{
				"resource": map[string]any{
					"resourceType": "Condition",
					"code": map[string]any{
						"coding": []map[string]any{
							{
								"system":  "http://hl7.org/fhir/sid/icd-10-cm",
								"code":    m.Diagnoses[0].Code,
								"display": m.Diagnoses[0].Description,
							},
						},
					},
				},
			},
		},
	}
	return json.MarshalIndent(bundle, "", "  ")
}
