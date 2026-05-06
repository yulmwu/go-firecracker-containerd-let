package httpserver

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"example.com/sandbox-demo/internal/model"
	"example.com/sandbox-demo/internal/sandbox"
	"github.com/gin-gonic/gin"
)

type Server struct {
	svc *sandbox.Service
}

func New(svc *sandbox.Service) *Server { return &Server{svc: svc} }

func (s *Server) Handler() http.Handler {
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	r.GET("/v1/sandboxes", s.list)
	r.GET("/v1/sandboxes/:id", s.get)
	r.POST("/v1/sandboxes", s.create)
	r.DELETE("/v1/sandboxes/:id", s.delete)
	r.POST("/v1/reconcile", s.reconcile)

	return r
}

func (s *Server) create(c *gin.Context) {
	var req model.CreateSandboxRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.ID == "" {
		req.ID = "sbx-" + time.Now().UTC().Format("20060102-150405")
	}

	sbx, err := s.svc.CreateSandbox(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"sandbox": sbx, "external_ip": externalIP(c.Request.Context())})
}

func (s *Server) get(c *gin.Context) {
	sbx, err := s.svc.GetSandbox(c.Request.Context(), c.Param("id"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"sandbox": sbx, "external_ip": externalIP(c.Request.Context())})
}

func (s *Server) list(c *gin.Context) {
	items, err := s.svc.ListSandboxes(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"items": items, "external_ip": externalIP(c.Request.Context())})
}

func (s *Server) delete(c *gin.Context) {
	if err := s.svc.DeleteSandbox(c.Request.Context(), c.Param("id")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"id": c.Param("id"), "phase": "deleted", "external_ip": externalIP(c.Request.Context())})
}

func (s *Server) reconcile(c *gin.Context) {
	if err := s.svc.ReconcileOnce(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "external_ip": externalIP(c.Request.Context())})
}

func externalIP(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "sh", "-c", "dig +short myip.opendns.com @resolver1.opendns.com")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
}
