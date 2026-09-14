package compiler

import (
	"context"
	"testing"

	"github.com/projectdiscovery/goja"
	"github.com/stretchr/testify/require"
)

// The goja fork builds the context.Context it injects into a library function
// out of every registered context value, so setting templateId on the runtime
// is all it takes to reach ctx.Value("templateId") inside pkg/js/libs. This
// test holds that whole path down: without it, a library reading templateId
// silently sees "" and its policy never engages.
func TestTemplateIdReachesLibraryContext(t *testing.T) {
	program, err := goja.Compile("", `probe()`, false)
	require.NoError(t, err)

	runtime := createNewRuntime()
	var (
		gotTemplateID  string
		gotExecutionID string
	)
	require.NoError(t, runtime.Set("probe", func(ctx context.Context) {
		gotTemplateID, _ = ctx.Value("templateId").(string)
		gotExecutionID, _ = ctx.Value("executionId").(string)
	}))

	_, err = executeWithRuntime(context.Background(), runtime, program, NewExecuteArgs(), &ExecuteOptions{
		ExecutionId: "execution-1",
		TemplateId:  "smb-default-login",
	}, nil)
	require.NoError(t, err)

	require.Equal(t, "smb-default-login", gotTemplateID)
	require.Equal(t, "execution-1", gotExecutionID, "the existing executionId path must still work")
}

// A caller that sets no template id leaves the value empty rather than
// inheriting the previous execution's, which would apply one template's policy
// to another's results on a pooled runtime.
func TestTemplateIdIsClearedBetweenExecutions(t *testing.T) {
	program, err := goja.Compile("", `probe()`, false)
	require.NoError(t, err)

	runtime := createNewRuntime()
	var gotTemplateID string
	require.NoError(t, runtime.Set("probe", func(ctx context.Context) {
		gotTemplateID, _ = ctx.Value("templateId").(string)
	}))

	_, err = executeWithRuntime(context.Background(), runtime, program, NewExecuteArgs(), &ExecuteOptions{
		ExecutionId: "execution-1",
		TemplateId:  "smb-default-login",
	}, nil)
	require.NoError(t, err)
	require.Equal(t, "smb-default-login", gotTemplateID)

	_, err = executeWithRuntime(context.Background(), runtime, program, NewExecuteArgs(), &ExecuteOptions{
		ExecutionId: "execution-2",
	}, nil)
	require.NoError(t, err)
	require.Equal(t, "", gotTemplateID, "template id leaked from the previous execution")

	_, ok := runtime.GetContextValue("templateId")
	require.False(t, ok, "template id must be removed from the runtime after execution")
}
