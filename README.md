# go-fiber-auth0-middleware
Auth0 middleware for Go Fiber

```go
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/gofiber/fiber/v2"
	auth0 "github.com/satishbabariya/go-fiber-auth0-middleware"
)

func main() {
	app := fiber.New()

	app.Use(auth0.New(auth0.Config{
		Issuer:   os.Getenv("AUTH0_ISSUER"),
		Audience: []string{os.Getenv("AUTH0_AUDIENCE")},
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return fiber.NewError(http.StatusUnauthorized, err.Error())
		},
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		claims := c.Locals("claims").(*validator.ValidatedClaims)
		return c.JSON(claims)
	})

	log.Fatal(app.Listen(":1203"))
}

```
