이 프로젝트는 containerd + gVisor(runsc) + CNI + iptables 기반으로, **같은 Sandbox 내부 컨테이너들이 `localhost`로 통신할 수 있는 구조**의 데모를 구현하는 것을 목표로 한다.

이는 Wargame/CTF 플랫폼에서 사용자에게 개별 인스턴스(샌드박스)를 제공하기 위한 접근인데, Kubernetes Pod의 네트워크 모델을 축소해서 직접 구현하는 형태라고 볼 수 있다. (Pod 대신 Sandbox)

이 프로젝트에서는 Go언어로 이러한 컨셉의 샌드박스 기능을 직접 구현해보는 것에 대해 데모로 구현합니다. 최종적으로 main.go에서 `CreateSandbox` 함수를 호출, 아래와 같은 정보가 제공될 수 있어야 합니다.

- 컨테이너 목록(복수 컨테이너 지원)
    - 컨테이너 이미지(예: nginx:stable, redis:latest, docker.io/library/nginx:stable 등)
    - 노출할 컨테이너 포트 및 프로토콜/매칭(예: 8080:80/tcp, 3000:3000, [호스트포트]:[컨테이너포트]/[프로토콜])
- Sandbox 네트워크 정책
    - 인터넷 outgoing 허용 여부 (기본적으로는 차단, 옵션으로 허용)
    - Sandbox 간 통신 허용 여부 (기본적으로는 차단, 옵션으로 허용)

이는 하나 이상의 컨테이너가 하나의 네트워크 네임스페이스를 공유하는 구조로, `localhost`로 서로 통신할 수 있어야 합니다. 노출 포트는 외부에서 해당 포트로 접근하면 Sandbox 내부의 컨테이너로 트래픽이 전달되어야 합니다. 
Sandbox 간 통신과 인터넷 접근은 iptables/nftables로 제어합니다.

단, 컨테이너에서 호스트로의 접근은 항상 매우 엄격하게 차단되어야 합니다. 호스트의 서비스나 리소스에 접근할 수 없어야 합니다.

# Demo 설계 문서: Containerd + gVisor(runsc) + CNI + iptables 기반 localhost-shared Sandbox

이 문서는 **같은 Sandbox 내부 컨테이너들이 `localhost`로 통신할 수 있는 구조**를 기준으로 한다.

따라서 이전의 “Docker Compose 스타일: 컨테이너별 독립 netns + bridge 통신” 구조는 폐기하고, 아래 구조로 확정한다.

```text
Sandbox
 ├─ pause container    ← network namespace 소유자
 ├─ app container A    ← pause netns 공유
 ├─ app container B    ← pause netns 공유
 └─ app container C    ← pause netns 공유
```

핵심 결론은 다음과 같다.

```text
1. Sandbox 하나당 pause container 하나를 둔다.
2. pause container가 Sandbox의 network namespace를 소유한다.
3. CNI는 pause container의 netns에 딱 한 번만 적용한다.
4. app container들은 모두 pause netns를 공유한다.
5. 따라서 app container끼리는 localhost로 통신할 수 있다.
6. Sandbox 외부와의 통신 제어는 Sandbox IP 기준 iptables/nftables로 처리한다.
7. 컨테이너 runtime은 gVisor(runsc)를 사용한다.
```

---

## 1. 데모의 목표

이 데모는 Kubernetes 전체를 쓰지 않고, **Pod의 핵심 네트워크 모델만 축소해서 직접 구현**하는 것을 목표로 한다.

Kubernetes Pod는 여러 컨테이너가 하나의 네트워크 네임스페이스를 공유하는 구조다. 이 문서의 Sandbox도 같은 원리를 사용한다. OCI Runtime Spec은 Linux namespace에 `path`를 지정하면 런타임이 해당 namespace에 컨테이너 프로세스를 넣어야 한다고 정의한다. 즉, Go 코드에서 app container의 network namespace path를 pause container의 netns path로 지정하면 같은 네트워크 공간을 공유할 수 있다. ([GitHub][1])

데모의 요구사항은 다음과 같다.

```text
필수 요구사항:
  - Sandbox 내부 컨테이너들은 localhost로 통신 가능해야 한다.
  - Sandbox 간 통신은 불가능해야 한다.
  - Sandbox에서 Host 접근은 불가능해야 한다.
  - 옵션에 따라 인터넷 outgoing을 차단할 수 있어야 한다.
  - Docker daemon 없이 containerd를 직접 제어한다.
  - 보안 강화를 위해 gVisor(runsc)를 사용한다.
```

---

## 2. 최종 아키텍처

```text
┌──────────────────────────────────────────────────────────────┐
│                         Host Linux                           │
│                                                              │
│  ┌──────────────────── Go Sandbox Service ─────────────────┐ │
│  │                                                        │ │
│  │  containerd SDK                                       │ │
│  │  libcni                                               │ │
│  │  go-iptables or nftables                              │ │
│  │  state manager                                        │ │
│  │  cleanup manager                                      │ │
│  │                                                        │ │
│  └────────────────────────────────────────────────────────┘ │
│              │                                               │
│              ▼                                               │
│  ┌────────────────────── containerd ───────────────────────┐ │
│  │                                                        │ │
│  │  socket: /run/containerd/containerd.sock               │ │
│  │  runtime: io.containerd.runsc.v1                       │ │
│  │  shim: containerd-shim-runsc-v1                        │ │
│  │                                                        │ │
│  └────────────────────────────────────────────────────────┘ │
│              │                                               │
│              ▼                                               │
│  ┌──────────────────── Sandbox sbx-001 ───────────────────┐  │
│  │                                                        │  │
│  │  shared netns: /run/netns/sbx-001                      │  │
│  │  sandbox IP: 10.88.1.2                                 │  │
│  │                                                        │  │
│  │  pause container                                       │  │
│  │    └─ owns netns                                       │  │
│  │                                                        │  │
│  │  app container: web                                    │  │
│  │    └─ uses /run/netns/sbx-001                          │  │
│  │                                                        │  │
│  │  app container: redis                                  │  │
│  │    └─ uses /run/netns/sbx-001                          │  │
│  │                                                        │  │
│  │  app container: worker                                 │  │
│  │    └─ uses /run/netns/sbx-001                          │  │
│  │                                                        │  │
│  │  web → redis: localhost:6379                           │  │
│  │  worker → web: localhost:8080                          │  │
│  │                                                        │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────── Sandbox sbx-002 ───────────────────┐  │
│  │                                                        │  │
│  │  shared netns: /run/netns/sbx-002                      │  │
│  │  sandbox IP: 10.88.2.2                                 │  │
│  │                                                        │  │
│  │  pause container                                       │  │
│  │  app container: web                                    │  │
│  │  app container: db                                     │  │
│  │                                                        │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  iptables/nftables:                                          │
│    - sbx-001 내부 localhost 통신은 netns 내부라 허용됨       │
│    - sbx-001 → sbx-002 차단                                  │
│    - sbx-001 → host 차단                                     │
│    - sbx-001 → internet은 옵션에 따라 허용/차단              │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## 3. 왜 pause container가 필요한가

`localhost` 공유는 **같은 network namespace를 공유할 때만** 가능하다.

컨테이너별 netns가 다르면 다음처럼 된다.

```text
container A의 127.0.0.1 ≠ container B의 127.0.0.1
```

그러나 shared netns를 쓰면 다음처럼 된다.

```text
container A의 127.0.0.1 == container B의 127.0.0.1
```

이 shared netns를 안정적으로 유지하려면 **항상 살아있는 netns 소유자**가 필요하다. 그 역할이 pause container다.

```text
pause container
  - 실제 비즈니스 로직은 없음
  - 거의 아무것도 하지 않음
  - Sandbox netns를 유지하는 역할
```

pause container가 없으면 다음 문제가 생긴다.

```text
app container A가 netns를 만들고,
app container B가 A의 netns를 공유한다고 가정

A가 죽음
→ netns 유지 주체가 사라짐
→ B의 네트워크 상태가 꼬이거나 cleanup이 어려워짐
```

따라서 구조는 다음으로 확정한다.

```text
Sandbox lifecycle = pause container lifecycle
```

---

## 4. 구성 요소 역할

### 4.1 Go Sandbox Service

직접 작성할 서비스다.

역할:

```text
- Sandbox 생성/삭제
- pause container 생성
- app container 생성
- containerd task 관리
- netns bind mount 관리
- CNI ADD/DEL 호출
- iptables/nftables rule 생성/삭제
- state 저장
- cleanup/reconcile
```

### 4.2 containerd

컨테이너 lifecycle을 담당한다.

containerd Go client는 container 생성, image pull, snapshot, task 실행 등을 API로 제어할 수 있다. containerd 공식 문서는 Go client에서 `/run/containerd/containerd.sock`에 연결하는 예제를 제공한다. ([Containerd][2])

### 4.3 gVisor(runsc)

gVisor는 일반 `runc` 대신 사용할 sandboxed runtime이다.

containerd에서는 `containerd-shim-runsc-v1`을 runtime handler로 등록해 사용한다. gVisor 공식 문서는 containerd runtime handler support를 통해 `containerd-shim-runsc-v1`을 사용하는 방식을 설명한다. ([gVisor][3])

Go 코드에서는 컨테이너 생성 시 다음 runtime을 지정한다.

```go
containerd.WithRuntime("io.containerd.runsc.v1", nil)
```

### 4.4 CNI

CNI는 pause container의 netns에 네트워크를 붙인다.

CNI는 Linux application container의 네트워크 설정을 plugin 기반으로 처리하기 위한 표준이다. CNI 명세는 container runtime과 network plugin 사이의 인터페이스를 정의한다. ([CNI][4])

이 데모에서는 다음 CNI plugin을 사용한다.

```text
bridge:
  - host에 bridge interface 생성
  - pause netns에 veth 연결

host-local:
  - Sandbox IP 할당

portmap:
  - 필요 시 hostPort → sandboxIP:containerPort 매핑

loopback:
  - netns 내부 lo 활성화
```

### 4.5 iptables 또는 nftables

Sandbox 외부 통신을 제어한다.

shared netns 구조에서는 Sandbox 내부 통신이 모두 같은 network namespace 안에서 일어나므로, app container 간 localhost 통신은 iptables FORWARD를 거치지 않는다.

iptables는 다음을 제어한다.

```text
- Sandbox → Host 접근 차단
- Sandbox → 다른 Sandbox 차단
- Sandbox → private network 차단
- Sandbox → public internet 허용/차단
- hostPort publish 허용/차단
```

---

## 5. Host 사전 설치

Ubuntu 기준이다.

### 5.1 기본 패키지

```bash
sudo apt update

sudo apt install -y \
  containerd \
  runc \
  iproute2 \
  iptables \
  curl \
  jq \
  tar \
  ca-certificates \
  gnupg \
  apparmor \
  apparmor-utils
```

확인:

```bash
containerd --version
ctr version
runc --version
iptables --version
ip -V
```

containerd 활성화:

```bash
sudo systemctl enable --now containerd
sudo systemctl status containerd
```

containerd socket:

```text
/run/containerd/containerd.sock
```

---

### 5.2 CNI plugins 설치

CNI plugin 바이너리는 일반적으로 `/opt/cni/bin`에 둔다. Kubernetes 문서에서도 CNI plugin이 필요하고, Kubernetes는 CNI specification v0.4.0 이상과 호환되는 plugin을 사용한다고 설명한다. ([Kubernetes][5])

2026-05-03 기준 GitHub releases에는 CNI plugins `v1.9.0`이 표시된다. 실제 운영에서는 버전을 고정하고 checksum 검증까지 넣는 것이 좋다. ([GitHub][6])

```bash
sudo mkdir -p /opt/cni/bin

CNI_VERSION="v1.9.0"
ARCH="amd64"

curl -L "https://github.com/containernetworking/plugins/releases/download/${CNI_VERSION}/cni-plugins-linux-${ARCH}-${CNI_VERSION}.tgz" \
  | sudo tar -C /opt/cni/bin -xz
```

확인:

```bash
ls -al /opt/cni/bin

test -x /opt/cni/bin/bridge
test -x /opt/cni/bin/host-local
test -x /opt/cni/bin/loopback
test -x /opt/cni/bin/portmap
```

---

### 5.3 gVisor(runsc) 설치

gVisor 공식 문서는 `runsc`를 release channel 또는 apt repository 방식으로 설치할 수 있다고 설명한다. 실험에는 nightly, production에는 latest release channel을 선택하라고 안내한다. ([gVisor][7])

Ubuntu apt repository 방식 예시:

```bash
curl -fsSL https://gvisor.dev/archive.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
  | sudo tee /etc/apt/sources.list.d/gvisor.list >/dev/null

sudo apt update
sudo apt install -y runsc
```

확인:

```bash
which runsc
which containerd-shim-runsc-v1 || true
runsc --version
```

반드시 다음 둘이 있어야 한다.

```text
runsc
containerd-shim-runsc-v1
```

`containerd-shim-runsc-v1`이 없다면 gVisor manual install 방식으로 shim 바이너리를 별도 설치해야 한다.

---

## 6. containerd에 runsc runtime 등록

기본 config 생성:

```bash
sudo mkdir -p /etc/containerd
sudo containerd config default | sudo tee /etc/containerd/config.toml >/dev/null
```

`/etc/containerd/config.toml`에 runtime 추가:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
```

재시작:

```bash
sudo systemctl restart containerd
```

확인:

```bash
ctr plugins ls | grep -i runsc || true
```

주의할 점:

```text
- CRI용 runtime handler 이름은 runsc로 둔다.
- Go SDK에서는 runtime type 문자열인 io.containerd.runsc.v1을 직접 지정한다.
- shim 바이너리가 PATH에 있어야 한다.
```

---

## 7. Go 프로젝트 구조

추천 구조:

```text
sandbox-demo/
  go.mod
  cmd/
    sandboxd/
      main.go

  internal/
    manager/
      manager.go
      create_sandbox.go
      delete_sandbox.go
      add_container.go
      cleanup.go

    runtime/
      containerd.go
      image.go
      spec.go
      task.go
      io.go

    network/
      cni.go
      netns.go
      firewall.go
      portmap.go

    model/
      sandbox.go
      container.go
      policy.go

    store/
      store.go
      file_store.go
```

---

## 8. Go dependency

containerd v2를 쓸 경우:

```bash
go mod init example.com/sandbox-demo

go get github.com/containerd/containerd/v2/client
go get github.com/containerd/containerd/v2/core/namespaces
go get github.com/containerd/containerd/v2/pkg/oci
go get github.com/opencontainers/runtime-spec/specs-go
go get github.com/containernetworking/cni/libcni
go get github.com/containernetworking/cni/pkg/types
go get github.com/containernetworking/cni/pkg/types/100
go get github.com/coreos/go-iptables/iptables
```

containerd v1 계열을 쓸 경우 import path가 다르다.

```bash
go get github.com/containerd/containerd
go get github.com/containerd/containerd/namespaces
go get github.com/containerd/containerd/oci
go get github.com/opencontainers/runtime-spec/specs-go
go get github.com/containernetworking/cni/libcni
go get github.com/coreos/go-iptables/iptables
```

문서와 코드에서는 **한 버전으로 고정**해야 한다. 새 프로젝트라면 v2 client를 추천하지만, 예제나 기존 자료는 v1 import가 많으므로 팀에서 통일해야 한다.

containerd v2 package 문서는 `NewContainer`, `WithNewSpec` 같은 container 생성 API를 제공한다. ([Go Packages][8])

---

## 9. 핵심 데이터 모델

### 9.1 Sandbox

```go
type Sandbox struct {
    ID          string
    Namespace   string

    NetNSPath   string
    IP          string
    GatewayIP   string
    SubnetCIDR  string
    BridgeName  string

    Egress      bool

    Pause       ContainerState
    Containers  map[string]ContainerState

    CNIConfPath string
    CreatedAt   time.Time
}
```

### 9.2 ContainerState

```go
type ContainerState struct {
    ID          string
    Name        string
    Image       string
    Args        []string
    Env         []string

    SnapshotKey string
    TaskPID     uint32

    Runtime     string
}
```

### 9.3 CreateSandboxRequest

```go
type CreateSandboxRequest struct {
    ID         string
    Egress     bool
    Containers []CreateContainerRequest
    Ports      []PortMapping
}
```

### 9.4 CreateContainerRequest

```go
type CreateContainerRequest struct {
    Name    string
    Image   string
    Args    []string
    Env     []string
    WorkDir string
    Limits  ResourceLimits
}
```

### 9.5 ResourceLimits

```go
type ResourceLimits struct {
    MemoryBytes int64
    CPUQuota    int64
    CPUPeriod   uint64
    PidsLimit   int64
}
```

### 9.6 PortMapping

shared netns 구조에서는 port mapping이 특정 container가 아니라 **Sandbox 전체**에 적용된다.

```go
type PortMapping struct {
    HostPort      int
    ContainerPort int
    Protocol      string
}
```

예:

```text
host:18080 → sandboxIP:8080
```

이때 `8080`을 실제로 어떤 app container가 listen하는지는 Sandbox 내부 설계 문제다.

---

## 10. Sandbox lifecycle

### 10.1 CreateSandbox 전체 흐름

```text
1. request validate
2. Sandbox ID 생성
3. subnet/bridge 이름 결정
4. CNI config 생성
5. pause image pull
6. pause container 생성
7. pause task start
8. pause task PID 획득
9. /proc/<pausePID>/ns/net을 /run/netns/<sandboxID>로 bind mount
10. CNI ADD를 pause netns에 1회 적용
11. Sandbox IP 파싱
12. firewall chain 생성
13. egress/host/private/Sandbox간 차단 정책 적용
14. app container image pull
15. app container 생성 시 pause netns path 지정
16. app task start
17. state 저장
```

### 10.2 DeleteSandbox 전체 흐름

```text
1. state 로드
2. app tasks kill/delete
3. app containers delete
4. CNI DEL
5. firewall chain 삭제
6. pause task kill/delete
7. pause container delete
8. netns bind mount umount
9. CNI config 삭제
10. snapshot cleanup
11. state 삭제
```

삭제는 반드시 idempotent해야 한다.

```text
- 이미 죽은 task는 무시
- 이미 없는 container는 무시
- 이미 없는 iptables chain은 무시
- CNI DEL 실패해도 나머지 cleanup 진행
```

---

## 11. CNI config 설계

shared netns 구조에서는 **Sandbox마다 하나의 CNI ADD**만 수행한다.

CNI config 예시:

```json
{
  "cniVersion": "1.0.0",
  "name": "sandbox-demo",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "sand0",
      "isGateway": true,
      "ipMasq": true,
      "hairpinMode": false,
      "ipam": {
        "type": "host-local",
        "ranges": [
          [
            {
              "subnet": "10.88.0.0/16",
              "gateway": "10.88.0.1"
            }
          ]
        ],
        "routes": [
          { "dst": "0.0.0.0/0" }
        ],
        "dataDir": "/var/lib/cni/sandbox-demo"
      }
    },
    {
      "type": "portmap",
      "capabilities": {
        "portMappings": true
      }
    }
  ]
}
```

추천 파일 위치:

```text
/etc/cni/net.d/10-sandbox-demo.conflist
```

단일 host에서 demo라면 bridge 하나를 공유해도 된다.

```text
bridge: sand0
subnet: 10.88.0.0/16
Sandbox A IP: 10.88.0.2
Sandbox B IP: 10.88.0.3
```

이 구조에서 Sandbox 간 통신은 같은 bridge 안에서 가능할 수 있으므로, iptables로 `sand0 → sand0` 트래픽을 정책에 따라 차단해야 한다.

더 강한 분리를 원하면 Sandbox마다 bridge/subnet을 동적으로 생성할 수도 있다. 다만 shared netns 구조의 핵심은 bridge 개수가 아니라 **Sandbox당 IP 하나 + shared netns 하나**다.

---

## 12. pause container 생성

### 12.1 pause image

추천 이미지:

```text
registry.k8s.io/pause:3.10
```

대체:

```text
busybox sleep infinity
```

데모에서는 pause 전용 이미지가 더 명확하다.

### 12.2 pause container 생성 코드 개념

v1 import 기준 예시:

```go
ctx := namespaces.WithNamespace(context.Background(), "sandbox-demo")

client, err := containerd.New("/run/containerd/containerd.sock")
if err != nil {
    return err
}

pauseImage, err := client.Pull(
    ctx,
    "registry.k8s.io/pause:3.10",
    containerd.WithPullUnpack,
)
if err != nil {
    return err
}

pauseContainer, err := client.NewContainer(
    ctx,
    sandboxID+"-pause",
    containerd.WithImage(pauseImage),
    containerd.WithNewSnapshot(sandboxID+"-pause-snapshot", pauseImage),
    containerd.WithRuntime("io.containerd.runsc.v1", nil),
    containerd.WithNewSpec(
        oci.WithImageConfig(pauseImage),
        withHardenedSpec(),
        withResourceLimits(defaultPauseLimits()),
    ),
)
if err != nil {
    return err
}
```

pause container도 gVisor runtime으로 실행한다.

```go
containerd.WithRuntime("io.containerd.runsc.v1", nil)
```

---

## 13. pause task 시작 및 netns 등록

pause task start:

```go
task, err := pauseContainer.NewTask(ctx, containerd.NewIO())
if err != nil {
    return err
}

if err := task.Start(ctx); err != nil {
    return err
}

pausePID := task.Pid()
```

netns source:

```go
source := fmt.Sprintf("/proc/%d/ns/net", pausePID)
target := fmt.Sprintf("/run/netns/%s", sandboxID)
```

추천은 symlink보다 bind mount다.

```bash
sudo mkdir -p /run/netns
sudo touch /run/netns/sbx-001
sudo mount --bind /proc/<pausePID>/ns/net /run/netns/sbx-001
```

Go에서는 `mount` syscall 또는 `exec.Command("mount", "--bind", ...)`를 사용할 수 있다.

```go
func bindMountNetNS(pid uint32, sandboxID string) (string, error) {
    target := filepath.Join("/run/netns", sandboxID)
    source := fmt.Sprintf("/proc/%d/ns/net", pid)

    if err := os.MkdirAll("/run/netns", 0755); err != nil {
        return "", err
    }

    _ = os.Remove(target)

    f, err := os.OpenFile(target, os.O_CREATE, 0644)
    if err != nil {
        return "", err
    }
    _ = f.Close()

    cmd := exec.Command("mount", "--bind", source, target)
    if out, err := cmd.CombinedOutput(); err != nil {
        return "", fmt.Errorf("bind mount netns: %w: %s", err, string(out))
    }

    return target, nil
}
```

삭제 시:

```bash
sudo umount /run/netns/sbx-001
sudo rm -f /run/netns/sbx-001
```

---

## 14. CNI ADD

CNI의 `RuntimeConf`는 CNI plugin 호출 1회에 필요한 `ContainerID`, `NetNS`, `IfName` 등을 담는다. libcni 문서는 `RuntimeConf`가 네트워크 설정을 제외한 CNI plugin invocation arguments를 가진다고 설명한다. ([Go Packages][9])

```go
cniConf := libcni.NewCNIConfig([]string{"/opt/cni/bin"}, nil)

netConf, err := libcni.ConfListFromFile("/etc/cni/net.d/10-sandbox-demo.conflist")
if err != nil {
    return err
}

rt := &libcni.RuntimeConf{
    ContainerID: sandboxID,
    NetNS:       netnsPath,
    IfName:      "eth0",
    Args: [][2]string{
        {"IgnoreUnknown", "1"},
    },
    CapabilityArgs: map[string]interface{}{},
}
```

hostPort가 필요한 경우:

```go
rt.CapabilityArgs["portMappings"] = []map[string]interface{}{
    {
        "hostPort":      18080,
        "containerPort": 8080,
        "protocol":      "tcp",
    },
}
```

CNI ADD:

```go
result, err := cniConf.AddNetworkList(ctx, netConf, rt)
if err != nil {
    return err
}
```

IP 파싱 후 state에 저장한다.

```text
Sandbox.IP = 10.88.0.2
```

중요:

```text
CNI ADD는 pause netns에만 수행한다.
app container마다 CNI ADD를 호출하지 않는다.
```

---

## 15. app container 생성: pause netns 공유

app container 생성 시 network namespace path를 지정한다.

```go
oci.WithLinuxNamespace(specs.LinuxNamespace{
    Type: specs.NetworkNamespace,
    Path: netnsPath,
})
```

예시:

```go
appImage, err := client.Pull(ctx, imageRef, containerd.WithPullUnpack)
if err != nil {
    return err
}

appContainer, err := client.NewContainer(
    ctx,
    sandboxID+"-"+name,
    containerd.WithImage(appImage),
    containerd.WithNewSnapshot(sandboxID+"-"+name+"-snapshot", appImage),
    containerd.WithRuntime("io.containerd.runsc.v1", nil),
    containerd.WithNewSpec(
        oci.WithImageConfig(appImage),
        oci.WithProcessArgs(args...),
        oci.WithLinuxNamespace(specs.LinuxNamespace{
            Type: specs.NetworkNamespace,
            Path: netnsPath,
        }),
        withHardenedSpec(),
        withResourceLimits(limits),
    ),
)
if err != nil {
    return err
}

task, err := appContainer.NewTask(ctx, containerd.NewIO())
if err != nil {
    return err
}

if err := task.Start(ctx); err != nil {
    return err
}
```

이렇게 생성된 app container들은 모두 같은 network namespace를 공유한다.

결과:

```text
web container:
  listen 127.0.0.1:8080

worker container:
  curl http://127.0.0.1:8080
  → 성공
```

---

## 16. localhost 공유 구조의 중요한 제약

### 16.1 포트 충돌

같은 netns를 쓰므로 포트 공간도 공유한다.

```text
web    listen :8080
worker listen :8080
```

이 경우 둘 중 하나는 실패한다.

따라서 Sandbox 내부 포트는 설계 단계에서 명확히 해야 한다.

예:

```text
web:    8080
redis:  6379
worker: outbound only
```

### 16.2 IP도 하나만 존재

Sandbox 전체가 IP 하나를 가진다.

```text
Sandbox IP: 10.88.0.2

web도 10.88.0.2
redis도 10.88.0.2
worker도 10.88.0.2
```

container별 IP는 없다.

### 16.3 네트워크 보안 경계는 Sandbox 단위

같은 Sandbox 내부 컨테이너끼리는 네트워크적으로 분리되지 않는다.

```text
같은 Sandbox 안에서는 서로 localhost 접근 가능
```

이건 요구사항을 만족하기 위해 의도적으로 선택한 구조다.

---

## 17. iptables 정책 설계

shared netns 구조에서는 정책 기준이 container가 아니라 Sandbox다.

```text
source IP = Sandbox IP
```

### 17.1 필요한 chain

전역 chain:

```text
SANDBOX-FWD
SANDBOX-IN
```

Sandbox별 chain:

```text
SBX-<short-id>-FWD
SBX-<short-id>-IN
```

역할:

```text
SANDBOX-FWD:
  Sandbox → 외부/다른 Sandbox 트래픽 제어

SANDBOX-IN:
  Sandbox → Host INPUT 트래픽 제어
```

왜 INPUT chain이 필요한가?

```text
Sandbox → Internet:
  host의 FORWARD chain을 통과

Sandbox → Host bridge gateway:
  host의 INPUT chain으로 들어옴
```

따라서 Host 접근 차단은 FORWARD만으로는 부족하다.

---

### 17.2 전역 chain 생성

```bash
iptables -N SANDBOX-FWD || true
iptables -I FORWARD 1 -j SANDBOX-FWD

iptables -N SANDBOX-IN || true
iptables -I INPUT 1 -j SANDBOX-IN
```

Go에서는 `AppendUnique` 또는 `Exists` 후 `Insert`를 사용한다.

```go
ipt, err := iptables.New(iptables.Timeout(5))
if err != nil {
    return err
}
```

---

### 17.3 Sandbox별 FORWARD chain

```bash
iptables -N SBX-abcd-FWD || true
iptables -A SANDBOX-FWD -s 10.88.0.2/32 -j SBX-abcd-FWD
```

정책 순서:

```text
1. established 허용
2. 다른 Sandbox/private/host 대역 차단
3. egress=true면 public internet 허용
4. egress=false면 전체 차단
```

egress=false:

```bash
iptables -A SBX-abcd-FWD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A SBX-abcd-FWD -d 10.88.0.0/16 -j REJECT
iptables -A SBX-abcd-FWD -d 10.0.0.0/8 -j REJECT
iptables -A SBX-abcd-FWD -d 172.16.0.0/12 -j REJECT
iptables -A SBX-abcd-FWD -d 192.168.0.0/16 -j REJECT
iptables -A SBX-abcd-FWD -d 169.254.0.0/16 -j REJECT

iptables -A SBX-abcd-FWD -j REJECT
```

egress=true:

```bash
iptables -A SBX-abcd-FWD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A SBX-abcd-FWD -d 10.88.0.0/16 -j REJECT
iptables -A SBX-abcd-FWD -d 10.0.0.0/8 -j REJECT
iptables -A SBX-abcd-FWD -d 172.16.0.0/12 -j REJECT
iptables -A SBX-abcd-FWD -d 192.168.0.0/16 -j REJECT
iptables -A SBX-abcd-FWD -d 169.254.0.0/16 -j REJECT

iptables -A SBX-abcd-FWD -j ACCEPT
```

주의:

```text
10.88.0.0/16은 Sandbox bridge 대역이다.
Sandbox A → Sandbox B를 막기 위해 차단한다.
같은 Sandbox 내부 localhost 통신은 FORWARD를 거치지 않으므로 영향 없다.
```

---

### 17.4 Sandbox별 INPUT chain

Sandbox에서 Host로 접근하는 것을 차단한다.

```bash
iptables -N SBX-abcd-IN || true
iptables -A SANDBOX-IN -i sand0 -s 10.88.0.2/32 -j SBX-abcd-IN
```

정책:

```bash
iptables -A SBX-abcd-IN -j REJECT
```

이렇게 하면 Sandbox에서 Host bridge gateway, Host local service 등에 접근하는 것을 막는다.

단, hostPort publish를 허용하는 경우에는 예외가 필요할 수 있다.

---

### 17.5 hostPort publish

CNI `portmap`을 쓰면 hostPort를 열 수 있다.

예:

```text
host:18080 → sandboxIP:8080
```

이때 Sandbox 내부에서 app container 중 하나가 `0.0.0.0:8080` 또는 `127.0.0.1:8080`에 listen해야 한다.

권장 정책:

```text
- 기본 hostPort publish 금지
- 필요한 경우 allowlist로만 허용
- hostPort 충돌 검사 필수
- privileged port(<1024)는 금지하거나 별도 승인
```

---

## 18. Hardened OCI spec

모든 app container에 기본 적용한다.

### 18.1 no-new-privileges

```go
s.Process.NoNewPrivileges = true
```

### 18.2 capability drop

```go
s.Process.Capabilities = &specs.LinuxCapabilities{
    Bounding:    []string{},
    Effective:   []string{},
    Inheritable: []string{},
    Permitted:   []string{},
    Ambient:     []string{},
}
```

주의:

```text
CAP_NET_BIND_SERVICE가 없으면 80 포트 bind가 안 될 수 있다.
Sandbox 내부 포트는 8080 이상을 쓰는 것을 추천한다.
```

### 18.3 readonly rootfs

```go
if s.Root != nil {
    s.Root.Readonly = true
}
```

필요 시 tmpfs mount:

```text
/tmp
/run
/var/tmp
```

### 18.4 masked paths

```go
s.Linux.MaskedPaths = []string{
    "/proc/acpi",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/sys/firmware",
}
```

### 18.5 readonly paths

```go
s.Linux.ReadonlyPaths = []string{
    "/proc/asound",
    "/proc/bus",
    "/proc/fs",
    "/proc/irq",
    "/proc/sys",
    "/proc/sysrq-trigger",
}
```

### 18.6 resource limits

```go
memory := int64(128 * 1024 * 1024)
pids := int64(128)
period := uint64(100000)
quota := int64(50000)

s.Linux.Resources = &specs.LinuxResources{
    Memory: &specs.LinuxMemory{
        Limit: &memory,
    },
    Pids: &specs.LinuxPids{
        Limit: pids,
    },
    CPU: &specs.LinuxCPU{
        Period: &period,
        Quota:  &quota,
    },
}
```

---

## 19. State 저장

반드시 저장해야 한다.

추천 경로:

```text
/var/lib/sandbox-demo/state/<sandboxID>.json
```

예:

```json
{
  "id": "sbx-001",
  "namespace": "sandbox-demo",
  "netNSPath": "/run/netns/sbx-001",
  "ip": "10.88.0.2",
  "gatewayIP": "10.88.0.1",
  "subnetCIDR": "10.88.0.0/16",
  "bridgeName": "sand0",
  "egress": false,
  "cniConfPath": "/etc/cni/net.d/10-sandbox-demo.conflist",
  "pause": {
    "id": "sbx-001-pause",
    "name": "pause",
    "image": "registry.k8s.io/pause:3.10",
    "snapshotKey": "sbx-001-pause-snapshot",
    "taskPID": 12345,
    "runtime": "io.containerd.runsc.v1"
  },
  "containers": {
    "web": {
      "id": "sbx-001-web",
      "name": "web",
      "image": "docker.io/library/nginx:latest",
      "snapshotKey": "sbx-001-web-snapshot",
      "taskPID": 12346,
      "runtime": "io.containerd.runsc.v1"
    },
    "worker": {
      "id": "sbx-001-worker",
      "name": "worker",
      "image": "docker.io/library/busybox:latest",
      "snapshotKey": "sbx-001-worker-snapshot",
      "taskPID": 12347,
      "runtime": "io.containerd.runsc.v1"
    }
  }
}
```

state가 없으면 cleanup이 어려워진다.

---

## 20. 구현 API 설계

### 20.1 Manager

```go
type Manager struct {
    client  *containerd.Client
    cni     *libcni.CNIConfig
    netConf *libcni.NetworkConfigList
    ipt     *iptables.IPTables
    store   Store
}
```

### 20.2 주요 메서드

```go
func (m *Manager) CreateSandbox(ctx context.Context, req CreateSandboxRequest) (*Sandbox, error)

func (m *Manager) AddContainer(ctx context.Context, sandboxID string, req CreateContainerRequest) error

func (m *Manager) DeleteSandbox(ctx context.Context, sandboxID string) error

func (m *Manager) ListSandboxes(ctx context.Context) ([]*Sandbox, error)

func (m *Manager) Reconcile(ctx context.Context) error
```

---

## 21. CreateSandbox pseudo code

```go
func (m *Manager) CreateSandbox(ctx context.Context, req CreateSandboxRequest) (*Sandbox, error) {
    ctx = namespaces.WithNamespace(ctx, "sandbox-demo")

    sbx := &Sandbox{
        ID:        req.ID,
        Namespace: "sandbox-demo",
        Egress:    req.Egress,
    }

    pause, err := m.createPauseContainer(ctx, sbx.ID)
    if err != nil {
        return nil, err
    }
    sbx.Pause = pause

    pauseTask, err := m.startTask(ctx, pause.ID)
    if err != nil {
        return nil, err
    }
    sbx.Pause.TaskPID = pauseTask.Pid()

    netnsPath, err := bindMountNetNS(sbx.Pause.TaskPID, sbx.ID)
    if err != nil {
        return nil, err
    }
    sbx.NetNSPath = netnsPath

    cniResult, err := m.attachCNI(ctx, sbx.ID, sbx.NetNSPath, req.Ports)
    if err != nil {
        return nil, err
    }
    sbx.IP = parseIP(cniResult)

    if err := m.applyFirewall(sbx.ID, sbx.IP, sbx.Egress); err != nil {
        return nil, err
    }

    sbx.Containers = map[string]ContainerState{}

    for _, c := range req.Containers {
        st, err := m.createAppContainer(ctx, sbx, c)
        if err != nil {
            return nil, err
        }
        sbx.Containers[c.Name] = st
    }

    if err := m.store.Save(sbx); err != nil {
        return nil, err
    }

    return sbx, nil
}
```

---

## 22. createAppContainer pseudo code

```go
func (m *Manager) createAppContainer(
    ctx context.Context,
    sbx *Sandbox,
    req CreateContainerRequest,
) (ContainerState, error) {
    image, err := m.client.Pull(ctx, req.Image, containerd.WithPullUnpack)
    if err != nil {
        return ContainerState{}, err
    }

    id := sbx.ID + "-" + req.Name
    snapshotKey := id + "-snapshot"

    container, err := m.client.NewContainer(
        ctx,
        id,
        containerd.WithImage(image),
        containerd.WithNewSnapshot(snapshotKey, image),
        containerd.WithRuntime("io.containerd.runsc.v1", nil),
        containerd.WithNewSpec(
            oci.WithImageConfig(image),
            oci.WithProcessArgs(req.Args...),
            oci.WithEnv(req.Env),
            oci.WithLinuxNamespace(specs.LinuxNamespace{
                Type: specs.NetworkNamespace,
                Path: sbx.NetNSPath,
            }),
            withHardenedSpec(),
            withResourceLimits(req.Limits),
        ),
    )
    if err != nil {
        return ContainerState{}, err
    }

    task, err := container.NewTask(ctx, containerd.NewIO())
    if err != nil {
        return ContainerState{}, err
    }

    if err := task.Start(ctx); err != nil {
        return ContainerState{}, err
    }

    return ContainerState{
        ID:          id,
        Name:        req.Name,
        Image:       req.Image,
        Args:        req.Args,
        Env:         req.Env,
        SnapshotKey: snapshotKey,
        TaskPID:     task.Pid(),
        Runtime:     "io.containerd.runsc.v1",
    }, nil
}
```

---

## 23. DeleteSandbox pseudo code

```go
func (m *Manager) DeleteSandbox(ctx context.Context, sandboxID string) error {
    ctx = namespaces.WithNamespace(ctx, "sandbox-demo")

    sbx, err := m.store.Load(sandboxID)
    if err != nil {
        return err
    }

    var errs []error

    for _, c := range sbx.Containers {
        if err := m.stopAndDeleteContainer(ctx, c.ID, c.SnapshotKey); err != nil {
            errs = append(errs, err)
        }
    }

    if err := m.detachCNI(ctx, sbx.ID, sbx.NetNSPath); err != nil {
        errs = append(errs, err)
    }

    if err := m.deleteFirewall(sbx.ID, sbx.IP); err != nil {
        errs = append(errs, err)
    }

    if err := m.stopAndDeleteContainer(ctx, sbx.Pause.ID, sbx.Pause.SnapshotKey); err != nil {
        errs = append(errs, err)
    }

    if err := unmountNetNS(sbx.NetNSPath); err != nil {
        errs = append(errs, err)
    }

    if err := m.store.Delete(sandboxID); err != nil {
        errs = append(errs, err)
    }

    return errors.Join(errs...)
}
```

삭제 순서에서 중요한 점:

```text
CNI DEL은 pause netns가 살아있는 동안 호출해야 한다.
따라서 pause container는 마지막에 죽인다.
```

---

## 24. 실행 예시

CLI 형태 예시:

```bash
sudo sandbox-demo create \
  --id sbx-001 \
  --egress=false \
  --port 18080:8080/tcp \
  --container web=docker.io/library/nginx:latest \
  --container worker=docker.io/library/busybox:latest
```

worker가 web에 접근:

```bash
curl http://127.0.0.1:8080
```

여기서 `127.0.0.1`은 worker container 자기 자신만이 아니라, **Sandbox shared netns의 localhost**다.

---

## 25. 테스트 플랜

### 25.1 runsc 사용 확인

```bash
ps aux | grep runsc
sudo ctr -n sandbox-demo tasks ls
```

### 25.2 netns 확인

```bash
sudo ip netns exec sbx-001 ip addr
sudo ip netns exec sbx-001 ip route
```

### 25.3 Sandbox 내부 localhost 확인

web container가 `:8080` listen한다고 가정:

```bash
# worker container 내부에서
curl http://127.0.0.1:8080
```

성공해야 한다.

### 25.4 Sandbox 간 통신 차단

```bash
sudo ip netns exec sbx-001 curl http://10.88.0.3:8080
```

실패해야 한다.

### 25.5 Host 접근 차단

```bash
sudo ip netns exec sbx-001 curl http://10.88.0.1
sudo ip netns exec sbx-001 curl http://169.254.169.254
```

실패해야 한다.

### 25.6 egress=false

```bash
sudo ip netns exec sbx-001 curl https://example.com
```

실패해야 한다.

### 25.7 egress=true

```bash
sudo ip netns exec sbx-002 curl https://example.com
```

성공해야 한다. 단, DNS가 필요하면 resolv.conf 설정도 필요하다.

---

## 26. DNS와 resolv.conf

shared netns 구조에서는 내부 컨테이너 간 통신에 DNS가 필요하지 않다.

```text
web → worker: localhost
worker → web: localhost
```

외부 인터넷 접근이 필요한 경우 DNS가 필요하다.

egress=false면 DNS도 막는 것이 맞다.

egress=true면 다음 중 하나를 선택한다.

```text
1. host의 /etc/resolv.conf를 그대로 사용
2. public DNS를 resolv.conf에 주입
3. Sandbox 전용 DNS proxy 사용
```

초기 데모에서는 가장 단순하게 host resolv.conf를 사용한다.

주의:

```text
nameserver가 private IP이면 iptables private 대역 차단에 걸릴 수 있다.
egress=true인데 DNS가 private resolver라면 DNS 예외를 추가해야 한다.
```

---

## 27. 보안 주의사항

### 27.1 containerd.sock mount 금지

절대 컨테이너에 mount하면 안 된다.

```text
/run/containerd/containerd.sock
/var/run/docker.sock
```

이 socket을 주면 사실상 host 제어권을 준 것과 같다.

### 27.2 privileged 금지

```text
privileged container 금지
CAP_SYS_ADMIN 금지
CAP_NET_ADMIN 금지
hostPID 금지
hostIPC 금지
hostNetwork 금지
device mount 금지
hostPath mount 금지
```

### 27.3 같은 Sandbox 내부는 신뢰 경계가 아니다

shared netns 구조에서는 같은 Sandbox 내부 컨테이너들이 서로 localhost로 접근할 수 있다.

즉:

```text
같은 Sandbox 내부 컨테이너끼리는 서로 네트워크적으로 격리되지 않는다.
```

이건 요구사항을 만족하기 위한 의도된 구조다.

### 27.4 gVisor 한계

gVisor는 보안을 강화하지만 VM과 동일한 보안 경계는 아니다. 더 강한 격리가 필요하면 Kata Containers 또는 Firecracker 같은 microVM 기반 구조를 별도로 검토해야 한다.

### 27.5 포트 충돌

shared netns에서는 포트 충돌이 매우 중요하다.

```text
web:    8080
admin:  8080
```

이런 설정은 허용하면 안 된다.

Sandbox 생성 시 port registry를 검사해야 한다.

---

## 28. 운영상 주의점

### 28.1 cleanup/reconcile 필수

프로세스가 중간에 죽으면 다음 리소스가 남을 수 있다.

```text
containerd container
containerd snapshot
CNI IPAM allocation
/run/netns bind mount
iptables chain
```

따라서 서비스 시작 시 reconcile을 수행한다.

```text
1. state 파일 목록 읽기
2. containerd 실제 상태 조회
3. 죽은 Sandbox cleanup
4. 남은 iptables chain cleanup
5. 남은 netns mount cleanup
```

### 28.2 CNI DEL은 pause가 살아있을 때

반드시 순서를 지킨다.

```text
올바른 순서:
  app stop
  CNI DEL
  firewall delete
  pause stop
  netns umount

잘못된 순서:
  pause stop
  CNI DEL
```

pause가 먼저 죽으면 netns가 사라져 CNI DEL이 실패하거나 cleanup이 불완전해질 수 있다.

### 28.3 iptables rule 순서

iptables는 순서가 중요하다.

권장 순서:

```text
FORWARD:
  1. SANDBOX-FWD 진입
  2. Sandbox IP별 chain 진입
  3. established 허용
  4. private/Sandbox/metadata 차단
  5. egress 정책 적용
```

INPUT:

```text
INPUT:
  1. SANDBOX-IN 진입
  2. bridge interface + Sandbox IP 기준 차단
```

---

## 29. 최종 확정 구조 요약

```text
이 데모는 pause container 기반 shared netns Sandbox 구조로 구현한다.
```

구성:

```text
containerd
  - container/task lifecycle

gVisor(runsc)
  - sandboxed runtime

pause container
  - Sandbox netns 소유

app containers
  - pause netns 공유
  - localhost 통신 가능

CNI
  - pause netns에만 ADD
  - Sandbox IP 하나 할당

iptables
  - Sandbox IP 기준 정책
  - Host 접근 차단
  - Sandbox 간 차단
  - egress 허용/차단

Go service
  - lifecycle 전체 관리
  - state 저장
  - cleanup/reconcile
```

가장 중요한 구현 규칙은 이 네 가지다.

```text
1. CNI는 pause container netns에만 적용한다.
2. app container는 반드시 pause netns path를 공유한다.
3. pause container는 Sandbox 삭제 직전까지 살아있어야 한다.
4. 방화벽 정책은 container 단위가 아니라 Sandbox IP 단위로 적용한다.
```

이 구조를 따르면 같은 Sandbox 내부에서는 `localhost`가 실질적으로 공유되고, Sandbox 외부와의 통신은 Sandbox 단위 정책으로 제어할 수 있다.

[1]: https://github.com/opencontainers/runtime-spec/blob/master/config-linux.md?utm_source=chatgpt.com "config-linux.md - opencontainers/runtime-spec"
[2]: https://containerd.io/docs/2.2/getting-started/?utm_source=chatgpt.com "containerd docs – Getting Started"
[3]: https://gvisor.dev/docs/user_guide/containerd/quick_start/?utm_source=chatgpt.com "Containerd Quick Start"
[4]: https://www.cni.dev/docs/spec/?utm_source=chatgpt.com "Container Network Interface (CNI) Specification"
[5]: https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/?utm_source=chatgpt.com "Network Plugins"
[6]: https://github.com/containernetworking/plugins/releases?utm_source=chatgpt.com "Releases · containernetworking/plugins"
[7]: https://gvisor.dev/docs/user_guide/install/?utm_source=chatgpt.com "Installation"
[8]: https://pkg.go.dev/github.com/containerd/containerd/v2/client?utm_source=chatgpt.com "client package - github.com/containerd/containerd/v2/client"

---

이 프로젝트에선 간단한 Demo로, 기본적인 Containerd 클라이언트, 네트워킹 설정, 등등의 구현 및 실제 동작을 보여주는 것을 목표로 한다.

따라서 복잡한 에러 처리, 고급 기능, 최적화 등은 다루지 않지만, 컨테이너 삭제시 발생할 수 있는 리소스 누수 방지 정도의 기본적인 안정성은 고려한다.

또한 LLM이 작업시 직접 필요한 도구(Containerd, gVisor, iptables 등등)를 설치하고 사용할 수 있다. sudo 시 암호는 `1424`이다. (모든 권한 허용함)
실제로 빌드가 되어야 하며, 실제로 Sandbox가 생성되고 삭제되는 것을 보여주는 것이 목표다. Sandbox는 2개 이상 만들고 서로 통신이 안 되는 것을 보여준다. 그리고 host 접근도 안 되는 것을 보여준다.
Sandbox 내부에선 localhost로 두개 이상의 컨테이너가 서로 통신이 가능하다는 것도 보여준다.

마지막으로 이러한 데모를 실행하기 위한 도구, 설정 파일 등을 자동으로 생성하는 `install.sh` 스크립트도 함께 제공한다.
이 스크립트는 필요한 바이너리를 설치하고, CNI config 파일을 생성하고, iptables 초기 설정을 하는 등의 작업을 수행한다.
이는 환경에 맞게, 에러처리도 깔끔하게 하면서 필요한 모든 설정을 자동으로 해주는 것을 목표로 한다.

---

## 30. 변경 사항 (2026-05-03)

이번 업데이트에서 프로젝트 기본 방향은 `runsc` 실험 상태에서 `runc` 안정 동작 중심으로 전환되었다.

핵심 변경:

```text
1) Runtime 프로파일 계층 도입
   - 기본값: runc (io.containerd.runc.v2)
   - 준비용 프로파일: runsc, kata, firecracker
   - 환경변수 SANDBOX_RUNTIME_PROFILE 로 선택 가능

2) Containerd endpoint 분리 지원
   - SANDBOX_CONTAINERD_ADDRESS 환경변수 지원
   - 추후 별도 containerd 데몬/런타임 백엔드 전환에 유리

3) 보안 기본값 강화
   - no_new_privileges=true
   - capability 전체 제거
   - read-only rootfs
   - writable tmpfs 최소화(/tmp, /run, /var/tmp)
   - masked/readonly proc 경로 적용
   - memory/cpu/pids 리소스 제한 기본 적용
   - RFC1918/metadata/loopback/multicast/reserved 대역 차단 강화

4) Manifest 기반 관리 기능 추가
   - sandboxd apply -f <manifest.yaml>
   - sandboxd deletef -f <manifest.yaml>
   - Kubernetes 스타일의 단순 Sandbox manifest 지원

5) 문서 추가
   - DOCS.md: 설치/빌드/실행/보안/manifest 사용 방법
   - examples.sandbox.yaml: 예시 매니페스트
```

주의:

```text
- runc는 커널 공유 모델이므로, runsc/kata/firecracker 대비 격리 강도는 낮다.
- 본 데모는 네트워크 차단과 하드닝 기본값을 강화했지만, 고강도 멀티테넌트 보안 경계는 VM 계열 런타임이 더 적합하다.
```
