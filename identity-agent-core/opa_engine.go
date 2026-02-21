package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"identity-agent-core/store"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

type OPAEngine struct {
	mu       sync.RWMutex
	modules  map[string]*ast.Module
	compiler *ast.Compiler
}

func NewOPAEngine() *OPAEngine {
	return &OPAEngine{
		modules: make(map[string]*ast.Module),
	}
}

func (e *OPAEngine) LoadPolicies(policies []store.RegoPolicy) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	modules := make(map[string]*ast.Module)
	for _, p := range policies {
		parsed, err := ast.ParseModule(p.Module, p.Rego)
		if err != nil {
			return fmt.Errorf("failed to parse policy '%s': %w", p.Name, err)
		}
		modules[p.Module] = parsed
	}

	compiler := ast.NewCompiler()
	compiler.Compile(modules)
	if compiler.Failed() {
		return fmt.Errorf("failed to compile policies: %v", compiler.Errors)
	}

	e.modules = modules
	e.compiler = compiler
	log.Printf("[opa] Loaded %d policies", len(policies))
	return nil
}

func (e *OPAEngine) AddPolicy(policy store.RegoPolicy) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	parsed, err := ast.ParseModule(policy.Module, policy.Rego)
	if err != nil {
		return fmt.Errorf("failed to parse policy '%s': %w", policy.Name, err)
	}

	e.modules[policy.Module] = parsed

	compiler := ast.NewCompiler()
	compiler.Compile(e.modules)
	if compiler.Failed() {
		delete(e.modules, policy.Module)
		return fmt.Errorf("failed to compile policies: %v", compiler.Errors)
	}

	e.compiler = compiler
	log.Printf("[opa] Added/updated policy: %s (module: %s)", policy.Name, policy.Module)
	return nil
}

func (e *OPAEngine) RemovePolicy(module string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	delete(e.modules, module)

	if len(e.modules) > 0 {
		compiler := ast.NewCompiler()
		compiler.Compile(e.modules)
		if !compiler.Failed() {
			e.compiler = compiler
		}
	} else {
		e.compiler = nil
	}
	log.Printf("[opa] Removed policy module: %s", module)
}

type EvalRequest struct {
	Query string      `json:"query"`
	Input interface{} `json:"input"`
}

type EvalResponse struct {
	Allow       bool        `json:"allow"`
	Results     interface{} `json:"results"`
	Decision    string      `json:"decision"`
	PolicyCount int         `json:"policy_count"`
}

func (e *OPAEngine) Evaluate(ctx context.Context, query string, input interface{}) (*EvalResponse, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.compiler == nil || len(e.modules) == 0 {
		return &EvalResponse{
			Allow:       false,
			Decision:    "no_policies_loaded",
			PolicyCount: 0,
		}, nil
	}

	r := rego.New(
		rego.Query(query),
		rego.Compiler(e.compiler),
		rego.Input(input),
	)

	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("evaluation failed: %w", err)
	}

	response := &EvalResponse{
		Allow:       false,
		Decision:    "deny",
		PolicyCount: len(e.modules),
	}

	if len(rs) > 0 && len(rs[0].Expressions) > 0 {
		val := rs[0].Expressions[0].Value
		response.Results = val

		switch v := val.(type) {
		case bool:
			response.Allow = v
			if v {
				response.Decision = "allow"
			}
		case map[string]interface{}:
			if allow, ok := v["allow"]; ok {
				if b, ok := allow.(bool); ok {
					response.Allow = b
					if b {
						response.Decision = "allow"
					}
				}
			}
		}
	}

	return response, nil
}

func (e *OPAEngine) ValidateRego(module, regoCode string) error {
	_, err := ast.ParseModule(module, regoCode)
	if err != nil {
		return fmt.Errorf("invalid Rego syntax: %w", err)
	}
	return nil
}

type SimulationRequest struct {
	PolicyID string      `json:"policy_id"`
	Query    string      `json:"query"`
	Events   interface{} `json:"events"`
}

type SimulationResult struct {
	TotalEvents int              `json:"total_events"`
	Allowed     int              `json:"allowed"`
	Denied      int              `json:"denied"`
	Details     []SimulationItem `json:"details"`
}

type SimulationItem struct {
	Event    interface{} `json:"event"`
	Decision string      `json:"decision"`
	Allow    bool        `json:"allow"`
}

func (e *OPAEngine) Simulate(ctx context.Context, regoCode string, module string, query string, events []interface{}) (*SimulationResult, error) {
	parsed, err := ast.ParseModule(module, regoCode)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}

	compiler := ast.NewCompiler()
	compiler.Compile(map[string]*ast.Module{module: parsed})
	if compiler.Failed() {
		return nil, fmt.Errorf("failed to compile policy: %v", compiler.Errors)
	}

	result := &SimulationResult{
		TotalEvents: len(events),
		Details:     make([]SimulationItem, 0),
	}

	for _, event := range events {
		r := rego.New(
			rego.Query(query),
			rego.Compiler(compiler),
			rego.Input(event),
		)

		rs, err := r.Eval(ctx)
		if err != nil {
			result.Details = append(result.Details, SimulationItem{
				Event:    event,
				Decision: "error",
				Allow:    false,
			})
			result.Denied++
			continue
		}

		allowed := false
		if len(rs) > 0 && len(rs[0].Expressions) > 0 {
			if b, ok := rs[0].Expressions[0].Value.(bool); ok {
				allowed = b
			}
		}

		decision := "deny"
		if allowed {
			decision = "allow"
			result.Allowed++
		} else {
			result.Denied++
		}

		result.Details = append(result.Details, SimulationItem{
			Event:    event,
			Decision: decision,
			Allow:    allowed,
		})
	}

	return result, nil
}

func marshalJSON(v interface{}) interface{} {
	data, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var result interface{}
	json.Unmarshal(data, &result)
	return result
}
