package cases

import (
	"context"
	"math"
	"time"

	"github.com/google/uuid"

	trustcfg "github.com/zero-trust/zero-trust-auth/trust/config"
	"github.com/zero-trust/zero-trust-auth/trust/internal/entities"
	pkgerrors "github.com/zero-trust/zero-trust-auth/toolkit/pkg/errors"
)

type EvaluateTrustInput struct {
	UserID      uuid.UUID
	Roles       []string
	IP          string
	UserAgent   string
	Fingerprint string
	Timestamp   time.Time
	Register    bool
}

type EvaluateTrustCase struct {
	devices      DeviceRepository
	loginHistory LoginHistoryRepository
	workingHours workingHoursGetter
	cache        TrustCache
	ipRep        IPReputation
	salt         string
	cfg          trustcfg.TrustConfig
}

type workingHoursGetter interface {
	Get(ctx context.Context, userID uuid.UUID) (start, end int, err error)
}

func NewEvaluateTrustCase(
	devices DeviceRepository,
	loginHistory LoginHistoryRepository,
	workingHours workingHoursGetter,
	cache TrustCache,
	ipRep IPReputation,
	salt string,
	cfg trustcfg.TrustConfig,
) *EvaluateTrustCase {
	return &EvaluateTrustCase{
		devices:      devices,
		loginHistory: loginHistory,
		workingHours: workingHours,
		cache:        cache,
		ipRep:        ipRep,
		salt:         salt,
		cfg:          cfg,
	}
}

func (c *EvaluateTrustCase) Execute(ctx context.Context, in EvaluateTrustInput) (*entities.TrustScore, error) {
	ipHash := hashStr(in.IP, c.salt)
	fpHash := hashStr(in.Fingerprint, c.salt)
	uaHash := hashStr(in.UserAgent, c.salt)

	deviceScore := 0.5
	if in.Fingerprint != "" {
		known, _ := c.devices.IsKnownDevice(ctx, in.UserID.String(), fpHash)
		deviceScore = boolScore(known)
	}
	knownDevice := deviceScore == 1.0

	var ipCountry, ipASN string
	ipRepScore := c.cfg.IPScore.UnknownScore
	if in.IP != "" {
		if info, err := c.ipRep.Lookup(ctx, in.IP); err == nil {
			switch {
			case info.IsDatacenter:
				ipRepScore = c.cfg.IPScore.DatacenterScore
			case info.IsTor:
				ipRepScore = c.cfg.IPScore.TorScore
			case info.Type == "residential":
				ipRepScore = c.cfg.IPScore.ResidentialScore
			default:
				ipRepScore = c.cfg.IPScore.UnknownScore
			}
			ipCountry = info.Country
			ipASN = info.ASN
		}
	}

	geoScore := c.geoAnomalyScore(ctx, in.UserID, ipCountry, in.Timestamp)
	todScore := c.timeOfDayScore(ctx, in.UserID, in.Timestamp)

	fails, _ := c.cache.GetFails(ctx, in.UserID)
	velScore := velocityScore(fails, c.cfg.Velocity)

	signals := []entities.RiskSignal{
		{Name: "device_known", Score: deviceScore, Weight: c.cfg.Signals.DeviceKnown.Weight},
		{Name: "ip_reputation", Score: ipRepScore, Weight: c.cfg.Signals.IPReputation.Weight},
		{Name: "geo_anomaly", Score: geoScore, Weight: c.cfg.Signals.GeoAnomaly.Weight},
		{Name: "time_of_day", Score: todScore, Weight: c.cfg.Signals.TimeOfDay.Weight},
		{Name: "velocity", Score: velScore, Weight: c.cfg.Signals.Velocity.Weight},
	}

	total := 0.0
	for _, s := range signals {
		total += s.Score * s.Weight
	}

	result := &entities.TrustScore{Value: total, Signals: signals}
	result.Decision = result.Decide(
		c.cfg.Thresholds.Allow,
		c.cfg.Thresholds.MFARequired,
		c.cfg.Thresholds.StepUp,
	)

	go func() {
		bgCtx := context.Background()
		if in.Register && !knownDevice && in.Fingerprint != "" {
			_ = c.devices.SaveDevice(bgCtx, in.UserID.String(), fpHash, uaHash)
			_ = c.cache.AddDevice(bgCtx, in.UserID, fpHash)
		}
		tc := &entities.TrustContext{
			UserID:          in.UserID,
			IPHash:          ipHash,
			Country:         ipCountry,
			ASN:             ipASN,
			UserAgent:       in.UserAgent,
			FingerprintHash: fpHash,
			Timestamp:       in.Timestamp,
		}
		_ = c.cache.SetLastContext(bgCtx, in.UserID, tc, 30*24*time.Hour)
		_ = c.loginHistory.Save(bgCtx, &LoginRecord{
			UserID:    in.UserID,
			IPHash:    ipHash,
			Country:   ipCountry,
			ASN:       ipASN,
			Timestamp: in.Timestamp,
		})
	}()

	return result, nil
}

func (c *EvaluateTrustCase) geoAnomalyScore(ctx context.Context, userID uuid.UUID, currentCountry string, now time.Time) float64 {
	lastCtx, err := c.cache.GetLastContext(ctx, userID)
	if err != nil {
		return c.cfg.GeoAnomaly.UnknownScore
	}

	hoursDiff := now.Sub(lastCtx.Timestamp).Hours()
	if hoursDiff <= 0 {
		hoursDiff = 0.001
	}

	curr, hasCurr := countryCentroids[currentCountry]
	last, hasLast := countryCentroids[lastCtx.Country]
	if !hasCurr || !hasLast {
		return c.cfg.GeoAnomaly.UnknownScore
	}

	dist := haversineKm(curr[0], curr[1], last[0], last[1])
	if dist/hoursDiff > c.cfg.GeoAnomaly.MaxSpeedKmh {
		return 0.0
	}
	return 1.0
}

func (c *EvaluateTrustCase) timeOfDayScore(ctx context.Context, userID uuid.UUID, ts time.Time) float64 {
	start, end, _ := c.workingHours.Get(ctx, userID)
	hour := ts.UTC().Hour()
	if hour >= start && hour <= end {
		return 1.0
	}
	return 0.5
}

func boolScore(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

func velocityScore(fails int64, cfg trustcfg.VelocityConfig) float64 {
	switch {
	case fails < cfg.LowThreshold:
		return cfg.LowScore
	case fails < cfg.HighThreshold:
		return cfg.MidScore
	default:
		return cfg.HighScore
	}
}

func isNotFound(err error) bool {
	return err != nil && err.Error() == pkgerrors.ErrNotFound.Error()
}

func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371.0
	φ1 := lat1 * math.Pi / 180
	φ2 := lat2 * math.Pi / 180
	Δφ := (lat2 - lat1) * math.Pi / 180
	Δλ := (lon2 - lon1) * math.Pi / 180
	a := math.Sin(Δφ/2)*math.Sin(Δφ/2) +
		math.Cos(φ1)*math.Cos(φ2)*math.Sin(Δλ/2)*math.Sin(Δλ/2)
	return R * 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}

var countryCentroids = map[string][2]float64{
	"AF": {33.94, 67.71}, "AR": {-38.42, -63.62}, "AU": {-25.27, 133.78},
	"AT": {47.52, 14.55}, "BE": {50.50, 4.47},    "BR": {-14.24, -51.93},
	"CA": {56.13, -106.35}, "CL": {-35.68, -71.54}, "CN": {35.86, 104.20},
	"CO": {4.57, -74.30},  "CZ": {49.82, 15.47},  "DK": {56.26, 9.50},
	"EG": {26.82, 30.80},  "FI": {61.92, 25.75},  "FR": {46.23, 2.21},
	"DE": {51.17, 10.45},  "GR": {39.07, 21.82},  "HU": {47.16, 19.50},
	"IN": {20.59, 78.96},  "ID": {-0.79, 113.92}, "IR": {32.43, 53.69},
	"IL": {31.05, 34.85},  "IT": {41.87, 12.57},  "JP": {36.20, 138.25},
	"KZ": {48.02, 66.92},  "KE": {-0.02, 37.91},  "KR": {35.91, 127.77},
	"MX": {23.63, -102.55}, "MA": {31.79, -7.09}, "NL": {52.13, 5.29},
	"NZ": {-40.90, 174.89}, "NG": {9.08, 8.68},   "NO": {60.47, 8.47},
	"PK": {30.38, 69.35},  "PL": {51.92, 19.15},  "PT": {39.40, -8.22},
	"RO": {45.94, 24.97},  "RU": {61.52, 105.32}, "SA": {23.89, 45.08},
	"ZA": {-30.56, 22.94}, "ES": {40.46, -3.75},  "SE": {60.13, 18.64},
	"CH": {46.82, 8.23},   "TW": {23.70, 121.00}, "TH": {15.87, 100.99},
	"TR": {38.96, 35.24},  "UA": {48.38, 31.17},  "GB": {55.38, -3.44},
	"US": {37.09, -95.71}, "UZ": {41.38, 64.59},  "VN": {14.06, 108.28},
}
