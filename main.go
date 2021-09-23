package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()
	router.LoadHTMLGlob("templates/*.html")
	router.Use(static.Serve("/styles", static.LocalFile("./styles", false)))
	router.Use(static.Serve("/jqwidgets", static.LocalFile("./jqwidgets", false)))
	router.Use(static.Serve("/scripts", static.LocalFile("./scripts", false)))
	router.Use(static.Serve("/sampledata", static.LocalFile("./sampledata", false)))

	router.GET("/", func(ctx *gin.Context) {
		ctx.HTML(200, "index.html", gin.H{})
	})

	router.GET("/form", func(ctx *gin.Context) {
		ctx.HTML(200, "form.html", gin.H{})
	})

	router.GET("/validform", func(ctx *gin.Context) {
		ctx.HTML(200, "validform.html", gin.H{})
	})

	router.GET("/jqgrid", func(ctx *gin.Context) {
		ctx.HTML(200, "jqgrid.html", gin.H{})
	})

	router.GET("/jqgridfilter", func(ctx *gin.Context) {
		ctx.HTML(200, "jqgridfilter.html", gin.H{})
	})

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"Cobrasonic"},
			Country:       []string{"Taiwan (R.O.C)"},
			Province:      []string{"Taipei City"},
			Locality:      []string{"Daan Dist."},
			StreetAddress: []string{"3F., No.7, Ln. 116, Guangfu S. Rd."},
			PostalCode:    []string{"106451"},
		},
		NotBefore: time.Now(),
		//AddDate(YEAR, MONTH, DAY)
		NotAfter:     time.Now().AddDate(20, 12, 365),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey

	// Sign the certificate
	certificate, _ := x509.CreateCertificate(rand.Reader, cert, cert, pub, priv)

	certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	keyBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	// Generate a key pair from your pem-encoded cert and key ([]byte).
	x509Cert, _ := tls.X509KeyPair(certBytes, keyBytes)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{x509Cert}}
	server := http.Server{Addr: ":3000", Handler: router, TLSConfig: tlsConfig}

	log.Println("router: ", router)
	err := server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal(err)
	}
}
