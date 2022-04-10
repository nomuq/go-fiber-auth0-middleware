package gofiberauth0middleware

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/gofiber/fiber/v2"
)

type Config struct {
	// Filter defines a function to skip middleware.
	// Optional. Default: nil
	Filter func(*fiber.Ctx) bool

	// SuccessHandler defines a function which is executed for a valid token.
	// Optional. Default: nil
	SuccessHandler fiber.Handler

	// ErrorHandler defines a function which is executed for an invalid token.
	// It may be used to define a custom JWT error.
	// Optional. Default: 401 Invalid or expired JWT
	ErrorHandler fiber.ErrorHandler

	Issuer             string        `yaml:"issuer"`
	Audience           []string      `yaml:"audience"`
	SignatureAlgorithm string        `yaml:"signature_algorithm"`
	CacheDuration      time.Duration `yaml:"cache_duration"`
}

func makeCfg(config []Config) (cfg Config) {
	if len(config) > 0 {
		cfg = config[0]
	}
	if cfg.SuccessHandler == nil {
		cfg.SuccessHandler = func(c *fiber.Ctx) error {
			return c.Next()
		}
	}
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = func(c *fiber.Ctx, err error) error {
			if err.Error() == "Missing or malformed JWT" {
				return c.Status(fiber.StatusBadRequest).SendString("Missing or malformed JWT")
			}
			return c.Status(fiber.StatusUnauthorized).SendString("Invalid or expired JWT")
		}
	}

	if cfg.CacheDuration == 0 {
		cfg.CacheDuration = 5 * time.Minute
	}

	if cfg.SignatureAlgorithm == "" {
		cfg.SignatureAlgorithm = "RS256"
	}

	return cfg
}

// jwtFromHeader returns a function that extracts token from the request header.
func jwtFromHeader(header string, authScheme string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		auth := c.Get(header)
		l := len(authScheme)
		if len(auth) > l+1 && strings.EqualFold(auth[:l], authScheme) {
			return auth[l+1:], nil
		}
		return "", errors.New("Missing or malformed JWT")
	}
}

func New(config ...Config) fiber.Handler {

	cfg := makeCfg(config)

	// Return middleware handler
	return func(c *fiber.Ctx) error {
		// Filter request to skip middleware
		if cfg.Filter != nil && cfg.Filter(c) {
			return c.Next()
		}

		issuerURL, err := url.Parse(cfg.Issuer)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		provider := jwks.NewCachingProvider(issuerURL, cfg.CacheDuration)

		// Set up the validator.
		jwtValidator, err := validator.New(
			provider.KeyFunc,
			validator.SignatureAlgorithm(cfg.SignatureAlgorithm),
			issuerURL.String(),
			cfg.Audience,
		)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		token, err := jwtFromHeader("Authorization", "Bearer")(c)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		// Get the JWT token from the request header.
		claims, err := jwtValidator.ValidateToken(c.Context(), token)
		if err != nil {
			fmt.Println(err)
			return cfg.ErrorHandler(c, err)
		}

		// Store user information from token into context.
		c.Locals("claims", claims)
		return cfg.SuccessHandler(c)
	}
}
