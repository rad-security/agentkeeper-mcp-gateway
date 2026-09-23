package detection

import "testing"

func TestCardCandidatesRequireLuhnForInputAndOutput(t *testing.T) {
	e := NewEngine()
	cases := []struct {
		name, text string
		detected   bool
	}{
		{"native numeric fidelity regression", `{"max_safe_integer":9007199254740991,"negative":-7,"fraction":0.125,"zero":0,"null":null}`, false},
		{"invalid checksum", "4242424242424241", false},
		{"all zeros", "0000000000000000", false},
		{"too long", "42424242424242424242", false},
		{"visa test card", "4242424242424242", true},
		{"spaces", "4242 4242 4242 4242", true},
		{"hyphens", "4242-4242-4242-4242", true},
		{"amex test card", "378282246310005", true},
		{"nineteen digits", "4000000000000000006", true},
		{"invalid then valid", "identifier 9007199254740991; card 4242424242424242", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, result := range []Result{e.EvaluateToolCall("synthetic", "lookup", map[string]interface{}{"text": tc.text}), e.EvaluateToolResponse("synthetic", "lookup", tc.text)} {
				if got := result.PatternName == "credit_card"; got != tc.detected {
					t.Fatalf("detected=%v want %v: %+v", got, tc.detected, result)
				}
			}
		})
	}
}
