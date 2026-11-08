package dlp

import (
	"fmt"
	"math/rand"
	"strings"
)

type EmployeeProfile struct {
	ID         string `json:"id"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	Email      string `json:"email"`
	PhoneUS    string `json:"phone_us"`
	PhoneE164  string `json:"phone_e164"`
	Department string `json:"department"`
	JobTitle   string `json:"job_title"`
	Street     string `json:"street"`
	City       string `json:"city"`
	State      string `json:"state"`
	ZIP        string `json:"zip"`
	SSN        string `json:"ssn"`
	Salary     int    `json:"salary"`
}

var firstNames = []string{"James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda", "David", "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica", "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa", "Matthew", "Margaret", "Anthony", "Betty", "Donald", "Sandra", "Mark", "Ashley", "Paul", "Dorothy", "Steven", "Kimberly", "Andrew", "Emily", "Kenneth", "Donna"}
var lastNames = []string{"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores"}
var departments = []string{"Engineering", "Information Security", "Finance", "Legal", "Human Resources", "Product Management", "Sales Operations", "Customer Support", "Executive"}
var jobTitles = []string{"Senior Software Engineer", "Staff Security Architect", "Financial Analyst", "Corporate Counsel", "HR Business Partner", "Lead Product Manager", "Enterprise Account Exec", "DevOps Engineer", "Director of Infrastructure"}
var streets = []string{"Market St", "Main St", "Silicon Way", "Park Ave", "Lexington Ave", "Oak St", "Pine Rd", "Cedar Ln", "Maple Blvd", "Washington St"}
var citiesStates = []struct{ City, State, ZIPPrefix string }{
	{"San Francisco", "CA", "941"},
	{"New York", "NY", "100"},
	{"Austin", "TX", "787"},
	{"Seattle", "WA", "981"},
	{"Chicago", "IL", "606"},
	{"Boston", "MA", "021"},
}

func GenerateRandomName(r *rand.Rand) string {
	return firstNames[r.Intn(len(firstNames))] + " " + lastNames[r.Intn(len(lastNames))]
}

func GenerateRandomPhone(r *rand.Rand) string {
	area := 200 + r.Intn(800)
	prefix := 200 + r.Intn(800)
	line := 1000 + r.Intn(9000)
	return fmt.Sprintf("(%d) %d-%04d", area, prefix, line)
}

func GenerateRandomAddress(r *rand.Rand) string {
	num := 100 + r.Intn(9900)
	street := streets[r.Intn(len(streets))]
	cs := citiesStates[r.Intn(len(citiesStates))]
	zip := fmt.Sprintf("%s%02d", cs.ZIPPrefix, r.Intn(100))
	return fmt.Sprintf("%d %s, %s, %s %s", num, street, cs.City, cs.State, zip)
}

func GenerateEmployeeProfile(r *rand.Rand, domain string) EmployeeProfile {
	fn := firstNames[r.Intn(len(firstNames))]
	ln := lastNames[r.Intn(len(lastNames))]
	if domain == "" {
		domain = "acme-corp.internal"
	}
	email := fmt.Sprintf("%s.%s@%s", strings.ToLower(fn), strings.ToLower(ln), domain)
	cs := citiesStates[r.Intn(len(citiesStates))]
	zip := fmt.Sprintf("%s%02d", cs.ZIPPrefix, r.Intn(100))
	area := 200 + r.Intn(800)
	pfx := 200 + r.Intn(800)
	line := 1000 + r.Intn(9000)

	return EmployeeProfile{
		ID:         fmt.Sprintf("EMP-%06d", r.Intn(1000000)),
		FirstName:  fn,
		LastName:   ln,
		Email:      email,
		PhoneUS:    fmt.Sprintf("(%d) %d-%04d", area, pfx, line),
		PhoneE164:  fmt.Sprintf("+1%d%d%04d", area, pfx, line),
		Department: departments[r.Intn(len(departments))],
		JobTitle:   jobTitles[r.Intn(len(jobTitles))],
		Street:     fmt.Sprintf("%d %s", 100+r.Intn(9900), streets[r.Intn(len(streets))]),
		City:       cs.City,
		State:      cs.State,
		ZIP:        zip,
		SSN:        GenerateSSN(r, true),
		Salary:     65000 + r.Intn(140000),
	}
}
