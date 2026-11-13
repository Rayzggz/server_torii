package config

import "testing"

func TestPortValidation(t *testing.T) {
	type portHolder struct {
		Port string `validate:"required,port"`
	}

	cases := []struct {
		port string
		ok   bool
	}{
		{"1", true},
		{"8080", true},
		{"25555", true},
		{"65535", true},
		{"0", false},
		{"65536", false},
		{"99999", false},
		{"-1", false},
		{"1.5", false},
		{"abc", false},
		{"", false},
	}

	for _, c := range cases {
		err := validate.Struct(portHolder{Port: c.port})
		if got := err == nil; got != c.ok {
			t.Errorf("port %q: valid = %v, want %v (err: %v)", c.port, got, c.ok, err)
		}
	}
}
