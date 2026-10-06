// cpscan 是集群配置安全基线本地扫描命令行。
//
// 子命令：
//
//	scan            扫描本地快照并输出稳定报表（支持增量与断点恢复）
//	exempt register 登记豁免（需授权主体）
//	exempt revoke   撤销豁免（需授权主体）
//	exempt list     列出豁免及其生效状态
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/huchangjun118/cluster-posture-scan-go/internal/baseline"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/exemption"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/model"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/report"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/scan"
	"github.com/huchangjun118/cluster-posture-scan-go/internal/snapshot"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "scan":
		err = cmdScan(os.Args[2:])
	case "exempt":
		err = cmdExempt(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  cpscan scan --snapshot DIR --baseline FILE [--version V] [--state FILE]
              [--exemptions FILE] [--out FILE] [--concurrency N] [--commit-every N]
  cpscan exempt register --exemptions FILE --audit FILE --actor NAME
              --id ID --check ID --kind KIND [--namespace NS] --name NAME
              --reason TEXT --expires RFC3339
  cpscan exempt revoke --exemptions FILE --audit FILE --actor NAME --id ID
  cpscan exempt list --exemptions FILE`)
}

func cmdScan(args []string) error {
	fs := newFlagSet("scan")
	snapshotDir := fs.String("snapshot", "", "snapshot directory")
	baselinePath := fs.String("baseline", "", "baseline file")
	version := fs.String("version", "", "baseline version (default: first in file)")
	statePath := fs.String("state", "", "state file for incremental scan and resume")
	exemptionsPath := fs.String("exemptions", "", "exemptions file")
	out := fs.String("out", "", "report output file (default: stdout)")
	concurrency := fs.Int("concurrency", 0, "evaluation concurrency")
	commitEvery := fs.Int("commit-every", 0, "commit state every N evaluated objects")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *snapshotDir == "" || *baselinePath == "" {
		return fmt.Errorf("--snapshot and --baseline are required")
	}

	objs, err := snapshot.LoadWithConcurrency(*snapshotDir, max(*concurrency, 1))
	if err != nil {
		return err
	}
	bl, err := baseline.LoadFile(*baselinePath, *version)
	if err != nil {
		return err
	}
	var active []exemption.Exemption
	if *exemptionsPath != "" {
		ex, err := exemption.Load(*exemptionsPath)
		if err != nil {
			return err
		}
		active = ex.Active(time.Now())
	}
	sc := &scan.Scanner{
		Baseline:    bl,
		StatePath:   *statePath,
		Exemptions:  active,
		Concurrency: *concurrency,
		CommitEvery: *commitEvery,
	}
	res, err := sc.Scan(objs)
	if err != nil {
		return err
	}
	data, err := report.Render(res)
	if err != nil {
		return err
	}
	if *out == "" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(*out, data, 0o644)
}

func cmdExempt(args []string) error {
	if len(args) < 1 {
		usage()
		return fmt.Errorf("exempt subcommand required")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "register":
		fs := newFlagSet("exempt register")
		path := fs.String("exemptions", "", "exemptions file")
		audit := fs.String("audit", "", "audit log file")
		actor := fs.String("actor", "", "acting principal")
		id := fs.String("id", "", "exemption id")
		check := fs.String("check", "", "check id")
		kind := fs.String("kind", "", "object kind")
		ns := fs.String("namespace", "", "object namespace")
		name := fs.String("name", "", "object name")
		reason := fs.String("reason", "", "justification")
		expires := fs.String("expires", "", "expiry time (RFC3339)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		store, err := exemption.Load(*path)
		if err != nil {
			return err
		}
		exp, err := time.Parse(time.RFC3339, *expires)
		if err != nil {
			return fmt.Errorf("invalid --expires: %w", err)
		}
		e := exemption.Exemption{
			ID: *id, CheckID: *check, Reason: *reason, ExpiresAt: exp,
			Ref: model.ObjectRef{Kind: *kind, Namespace: *ns, Name: *name},
		}
		if err := store.Register(e, *actor, *audit); err != nil {
			return err
		}
		return store.Save(*path)
	case "revoke":
		fs := newFlagSet("exempt revoke")
		path := fs.String("exemptions", "", "exemptions file")
		audit := fs.String("audit", "", "audit log file")
		actor := fs.String("actor", "", "acting principal")
		id := fs.String("id", "", "exemption id")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		store, err := exemption.Load(*path)
		if err != nil {
			return err
		}
		if err := store.Revoke(*id, *actor, *audit); err != nil {
			return err
		}
		return store.Save(*path)
	case "list":
		fs := newFlagSet("exempt list")
		path := fs.String("exemptions", "", "exemptions file")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		store, err := exemption.Load(*path)
		if err != nil {
			return err
		}
		now := time.Now()
		for _, e := range store.Exemptions {
			status := "active"
			if e.Revoked {
				status = "revoked"
			} else if !now.Before(e.ExpiresAt) {
				status = "expired"
			}
			fmt.Printf("%s\t%s\t%s\t%s\texpires=%s\tby=%s\n",
				e.ID, e.CheckID, e.Ref.Key(), status, e.ExpiresAt.Format(time.RFC3339), e.CreatedBy)
		}
		return nil
	default:
		usage()
		return fmt.Errorf("unknown exempt subcommand %q", sub)
	}
}
