package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/baseline"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/exemption"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/object"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/report"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/scan"
)

const usage = `scanner - local cluster configuration baseline scanner

Usage:
  scanner scan     --snapshot DIR [--baseline VER] [--incremental] [options]
  scanner versions
  scanner exempt   grant  --check ID --kind K --namespace NS --name N
                   --expires RFC3339 [--reason TXT] [--actor A]
  scanner exempt   revoke --id EX-ID [--actor A]
  scanner exempt   list
  scanner inspect  --snapshot DIR

Options:
  --state DIR       Directory for review/exemption state (default ./.scan-state)
  --workers N       Evaluation concurrency (default 4)
  --format F        json (default, byte-stable) or text
  --as-of RFC3339   Pin evaluation time; makes output fully reproducible
`

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "scan":
		err = cmdScan(args[1:])
	case "versions":
		err = cmdVersions()
	case "exempt":
		err = cmdExempt(args[1:])
	case "inspect":
		err = cmdInspect(args[1:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n%s", args[0], usage)
		return 2
	}
	if err != nil {
		var interrupted *scan.InterruptedError
		if errors.As(err, &interrupted) {
			fmt.Fprintf(os.Stderr, "scan interrupted; progress committed, rerun to resume: %v\n", err)
			return 3
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	snapshot := fs.String("snapshot", "", "snapshot directory")
	ver := fs.String("baseline", "", "baseline version (default latest)")
	stateDir := fs.String("state", "./.scan-state", "state directory")
	workers := fs.Int("workers", 4, "evaluation concurrency")
	format := fs.String("format", "json", "report format: json|text")
	asOf := fs.String("as-of", "", "pin evaluation time (RFC3339)")
	incremental := fs.Bool("incremental", false, "incremental review since last committed scan")
	commitEvery := fs.Int("commit-every", 1, "units between checkpoints")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *snapshot == "" {
		return fmt.Errorf("--snapshot is required")
	}
	reg, err := baseline.BuiltinRegistry()
	if err != nil {
		return err
	}
	bv := baseline.Version(*ver)
	if bv == "" {
		bv, err = reg.Latest()
		if err != nil {
			return err
		}
	}
	store, err := exemption.OpenStore(*stateDir + "/exemptions.json")
	if err != nil {
		return err
	}
	var pinned time.Time
	if *asOf != "" {
		pinned, err = time.Parse(time.RFC3339, *asOf)
		if err != nil {
			return fmt.Errorf("parse --as-of: %w", err)
		}
	}
	snap, err := object.NewLoader(*snapshot, *workers).Load()
	if err != nil {
		return err
	}
	eng := scan.NewEngine(reg, store, scan.Config{
		Workers:     *workers,
		StateDir:    *stateDir,
		BaselineVer: bv,
		AsOf:        pinned,
		CommitEvery: *commitEvery,
	})
	var res *scan.Result
	if *incremental {
		res, err = eng.ReviewIncrementally(snap)
	} else {
		res, err = eng.FullScan(snap)
	}
	if err != nil {
		return err
	}
	return report.Write(os.Stdout, res, report.Options{Format: report.Format(*format)})
}

func cmdVersions() error {
	reg, err := baseline.BuiltinRegistry()
	if err != nil {
		return err
	}
	for _, v := range reg.Versions() {
		b, _ := reg.Get(v)
		fmt.Printf("%s (%d checks)\n", v, len(b.Checks))
	}
	return nil
}

func cmdInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	snapshot := fs.String("snapshot", "", "snapshot directory")
	workers := fs.Int("workers", 4, "parse concurrency")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *snapshot == "" {
		return fmt.Errorf("--snapshot is required")
	}
	snap, err := object.NewLoader(*snapshot, *workers).Load()
	if err != nil {
		return err
	}
	fmt.Printf("snapshot_id: %s\n", snap.ID())
	fmt.Printf("objects: %d\n", len(snap.Objects))
	for _, m := range snap.Merges {
		fmt.Printf("merged %s: winner=%s conflicts=%d\n", m.Key.String(), m.Winner, len(m.Conflicts))
		for _, c := range m.Conflicts {
			fmt.Printf("  - %s -> %q\n", c.Field, c.Resolved)
		}
	}
	return nil
}

func cmdExempt(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("exempt requires grant|revoke|list")
	}
	switch args[0] {
	case "grant":
		return cmdExemptGrant(args[1:])
	case "revoke":
		return cmdExemptRevoke(args[1:])
	case "list":
		return cmdExemptList(args[1:])
	default:
		return fmt.Errorf("unknown exempt subcommand %q", args[0])
	}
}

func openExemptionStore(stateDir string) (*exemption.Store, error) {
	return exemption.OpenStore(stateDir + "/exemptions.json")
}

func cmdExemptGrant(args []string) error {
	fs := flag.NewFlagSet("exempt grant", flag.ContinueOnError)
	stateDir := fs.String("state", "./.scan-state", "state directory")
	checkID := fs.String("check", "", "check id to suppress")
	kind := fs.String("kind", "", "object kind")
	ns := fs.String("namespace", "", "object namespace")
	name := fs.String("name", "", "object name")
	expires := fs.String("expires", "", "expiry time RFC3339")
	reason := fs.String("reason", "", "reason")
	actor := fs.String("actor", "admin", "acting identity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *checkID == "" || *kind == "" || *name == "" || *expires == "" {
		return fmt.Errorf("--check, --kind, --name and --expires are required")
	}
	exp, err := time.Parse(time.RFC3339, *expires)
	if err != nil {
		return fmt.Errorf("parse --expires: %w", err)
	}
	store, err := openExemptionStore(*stateDir)
	if err != nil {
		return err
	}
	e, err := store.Grant(*actor, exemption.Exemption{
		CheckID: *checkID, ObjectKind: *kind, Namespace: *ns, Name: *name,
		Reason: *reason, ExpiresAt: exp,
	})
	if err != nil {
		return err
	}
	fmt.Printf("granted %s (expires %s)\n", e.ID, e.ExpiresAt.Format(time.RFC3339))
	return nil
}

func cmdExemptRevoke(args []string) error {
	fs := flag.NewFlagSet("exempt revoke", flag.ContinueOnError)
	stateDir := fs.String("state", "./.scan-state", "state directory")
	id := fs.String("id", "", "exemption id")
	actor := fs.String("actor", "admin", "acting identity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("--id is required")
	}
	store, err := openExemptionStore(*stateDir)
	if err != nil {
		return err
	}
	return store.Revoke(*actor, *id, time.Now())
}

func cmdExemptList(args []string) error {
	fs := flag.NewFlagSet("exempt list", flag.ContinueOnError)
	stateDir := fs.String("state", "./.scan-state", "state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := openExemptionStore(*stateDir)
	if err != nil {
		return err
	}
	for _, e := range store.All() {
		state := "active"
		if !e.Active(time.Now()) {
			state = "inactive"
		}
		fmt.Printf("%s [%s] %s %s/%s/%s expires=%s by=%s\n",
			e.ID, state, e.CheckID, e.ObjectKind, e.Namespace, e.Name,
			e.ExpiresAt.Format(time.RFC3339), e.CreatedBy)
	}
	return nil
}
