# SOC Chain Monitor
https://soc-chain-monitor.onrender.com --> live demo
A SOC-style log monitoring tool with **detection rules** and **blockchain-anchored tamper evidence**.

Security logs are batched, hashed into a Merkle tree, and the tree's root is written to a smart
contract. Detection rules flag suspicious activity, and a dashboard lets an analyst verify any
batch against the blockchain - so an attacker who edits the logs (even one who also rewrites the
local database) is caught.

## What it does

| Area | Feature |
|---|---|
| Ingest | `POST /logs/ingest`, `POST /logs/seal-batch` (SQLite storage, survives restarts) |
| Detection | brute force, success-after-brute-force, off-hours login, privilege escalation, audit logging disabled, root account usage |
| Blockchain | `LogAnchor.sol` stores one Merkle root per batch, **write-once**; local Hardhat node or Sepolia testnet |
| Verification | `GET /logs/batch/{id}/integrity`, `POST /logs/verify` - **fail closed** (no chain = `UNVERIFIABLE`, never "ok") |
| Dashboard | `http://127.0.0.1:8000/dashboard` - alerts, batches, per-log verify, live tamper demo |
| Quality | pytest suite, Hardhat contract tests, GitHub Actions CI |

## Layout

```
backend/            FastAPI app (app/), tests (tests/)
  app/config.py     settings from environment variables
  app/merkle.py     hardened Merkle tree
  app/storage.py    SQLite storage
  app/chain.py      web3.py client (unlocked or signed transactions)
  app/detection.py  detection rules
  app/security.py   API-key protection
  app/main.py       API
  app/static/       dashboard (html / css / js)
contracts/          Hardhat project: LogAnchor.sol, deploy script, tests
.github/workflows/  CI
```

## Quickest way to run it (simulated ledger, no blockchain node)

```powershell
cd backend
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
$env:SOC_CHAIN_MODE = "simulated"
$env:SOC_DEMO_MODE = "1"
python -m uvicorn app.main:app --reload
```
Open http://localhost:8000 (landing) and http://localhost:8000/dashboard (console). The status chip must read
**SIMULATED ledger**. Click *Load sample attack*, open the batch, *Verify integrity on-chain* (INTACT),
then *Tamper + rewrite local root* - the Merkle tree turns red and the verdict is TAMPERED.

The simulated ledger is a write-once table in the same SQLite file. It behaves like the contract for demos but is
**not a real blockchain**; the UI says so. Leave `SOC_CHAIN_MODE` unset (or `real`) to use Hardhat or Sepolia.

## Deploy the demo on Render

Push the repo to GitHub, then in Render choose *New > Blueprint* and select it (`render.yaml` is included), or create a
Web Service by hand with Root Directory `backend`, Build `pip install -r requirements.txt`, Start
`python -m uvicorn app.main:app --host 0.0.0.0 --port $PORT`, and these environment variables:

| Variable | Value |
|---|---|
| `PYTHON_VERSION` | `3.12.7` |
| `SOC_CHAIN_MODE` | `simulated` |
| `SOC_DEMO_MODE` | `1` |
| `SOC_API_KEY` | any long random string (type it into the dashboard's API key box) |

On the free tier the database resets on restart; click *Load sample attack* again.

## Run it with a real local blockchain (Windows / PowerShell, three terminals)

**Terminal 1 - blockchain** (leave running)
```powershell
cd contracts
npm install
npx hardhat compile
npx hardhat node
```

**Terminal 2 - deploy the contract** (repeat after every restart of Terminal 1)
```powershell
cd contracts
npx hardhat run scripts/deploy.js --network localhost
```

**Terminal 3 - backend**
```powershell
cd backend
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
$env:SOC_DEMO_MODE = "1"            # enables the attack simulation (demos only)
python -m uvicorn app.main:app --reload
```
Open **http://127.0.0.1:8000/dashboard**, click **Load sample attack**, open the batch, click
**Verify integrity** (INTACT), then **Tamper + rewrite local root** and verify again (TAMPERED).

If PowerShell blocks `Activate.ps1`, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first.

## Tests

```powershell
cd backend
python -m pytest -q                       # chain tests skip unless a node + deployed contract exist
cd ..\contracts
npx hardhat test                          # smart-contract tests (in-process, no node needed)
```
To include the signed-transaction test, export a *local* Hardhat test key first:
`$env:TEST_CHAIN_PRIVATE_KEY = "0x..."` (pick one printed by `npx hardhat node`).

## Security settings

| Variable | Purpose |
|---|---|
| `SOC_API_KEY` | When set, `ingest`, `seal-batch`, `anchor`, `detect` (and demo) need header `X-API-Key`. In `/docs` use the **Authorize** button; in the dashboard use the API-key box. |
| `SOC_DEMO_MODE` | `1` enables `/demo/tamper`. Leave off in anything but a demo. |
| `SOC_MAX_PENDING` | Cap on un-sealed logs (default 10000). |

See `.env.example` for every variable. Never commit keys; `.env` is git-ignored.

## Deploy to the Sepolia testnet

1. Create a **throwaway** wallet (e.g. MetaMask) and get Sepolia test ETH from a faucet.
2. Get a Sepolia RPC URL (Alchemy, Infura, or another provider).
3. Deploy:
   ```powershell
   cd contracts
   $env:SEPOLIA_RPC_URL = "https://..."
   $env:DEPLOYER_PRIVATE_KEY = "0x..."
   npx hardhat run scripts/deploy.js --network sepolia
   ```
4. Start the backend with the same RPC and key so it signs transactions itself:
   ```powershell
   cd backend
   $env:CHAIN_RPC_URL = "https://..."
   $env:CHAIN_PRIVATE_KEY = "0x..."
   python -m uvicorn app.main:app
   ```
   The dashboard chip should read `connected (signed, chain 11155111)` and each batch links to Etherscan.

The backend refuses to talk to a contract deployed on a different chain than the node it reached.

## How verification works (and its limits)

- The **on-chain root is the only trusted reference**. The locally stored root is shown for comparison but never trusted.
- `INTACT` = logs recomputed from the database match the on-chain root. `TAMPERED` = they do not.
  `UNVERIFIABLE` = the chain could not be reached or has no root. `UNANCHORED` = the batch was never anchored.
- Anchoring proves the logs have not changed **since the moment of anchoring**. It cannot prove what happened
  before. `POST /logs/batch/{id}/anchor` therefore refuses to anchor a batch whose logs changed since sealing.
- Detection correlates events by the `actor` field only (no IP/geo correlation).
- The detection rules, thresholds and hours are defaults to tune, not a substitute for a real SIEM.
