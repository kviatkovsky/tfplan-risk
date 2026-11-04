package engine

import (
	"math"

	"github.com/kviatkovsky/tfplan-risk/rules"
)

// Weights are the points each active finding adds before saturation.
// See docs/adr/0003-scoring-model.md.
var Weights = map[rules.Severity]float64{
	rules.SeverityCritical: 40,
	rules.SeverityHigh:     15,
	rules.SeverityMedium:   5,
	rules.SeverityLow:      1,
	rules.SeverityInfo:     0,
}

// Saturation controls how fast the score approaches 100: a raw sum equal to
// Saturation maps to ~63.
const Saturation = 50.0

// Score maps findings to 0-100: score = round(100 * (1 - e^(-sum/Saturation)))
// where sum is the weighted count of active (non-suppressed) findings. Each
// extra finding adds less than the previous one, and the score never reaches
// 100 exactly from a finite number of findings, except through rounding.
func Score(findings []Finding) int {
	var sum float64
	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		sum += Weights[f.Severity]
	}
	return int(math.Round(100 * (1 - math.Exp(-sum/Saturation))))
}
