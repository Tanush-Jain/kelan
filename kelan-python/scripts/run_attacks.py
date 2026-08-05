import sys
import asyncio
import httpx
import uuid
import secrets
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent))

console = Console()

async def run_scenario(scenario_name, description, func):
    console.print(Panel(f"[bold yellow]Scenario: {scenario_name}[/bold yellow]\n[dim]{description}[/dim]", border_style="yellow"))
    try:
        await func()
    except Exception as e:
        console.print(f"[bold red]Scenario encountered an error: {e}[/bold red]")
    console.print("\n" + "─"*60 + "\n")

async def test_clean_enroll(client, base_url):
    entity_id = f"agent-clean-{secrets.token_hex(4)}"
    payload = {
        "entity_id": entity_id,
        "name": "clean-telemetry-sensor",
        "version": "1.0.0",
        "intent": "Relay authenticated IoT telemetry data every 10 seconds",
        "source_ip": "192.168.1.100",
        "kem_public_key": f"kem-pub-{secrets.token_hex(20)}",
        "signature": secrets.token_hex(64)
    }
    
    resp = await client.post(f"{base_url}/api/enroll", json=payload)
    if resp.status_code == 200:
        data = resp.json()
        console.print("[bold green]✓ Accepted: Clean enrollment succeeded![/bold green]")
        console.print(f"  [bold]Verdict:[/bold] {data.get('verdict')} | [bold]Reason:[/bold] {data.get('reason')} | [bold]Permit Token:[/bold] {data.get('permit_token')}")
    else:
        console.print(f"[bold red]✗ Rejected (HTTP {resp.status_code}): {resp.text}[/bold red]")

async def test_sybil_attack(client, base_url):
    # Send 12 rapid requests to trigger ENROLL_BURST_LIMIT (10)
    console.print("Sending 12 rapid enrollment requests to trigger Sybil burst detection...")
    entity_id = f"agent-sybil-{secrets.token_hex(4)}"
    
    tasks = []
    for i in range(12):
        payload = {
            "entity_id": entity_id,
            "name": f"attacker-clone-{i}",
            "version": "1.0.0",
            "intent": "INIT_ENROL",
            "source_ip": "10.0.0.99",
            "kem_public_key": f"kem-pub-{secrets.token_hex(20)}",
            "signature": secrets.token_hex(64)
        }
        tasks.append(client.post(f"{base_url}/api/enroll", json=payload))
        
    responses = await asyncio.gather(*tasks, return_exceptions=True)
    
    success_count = 0
    denied_count = 0
    
    for r in responses:
        if isinstance(r, Exception):
            continue
        if r.status_code == 200:
            success_count += 1
        elif r.status_code == 403:
            denied_count += 1
            
    console.print(f"[bold]Results:[/bold] Approved={success_count}, Blocked/Refused={denied_count}")
    if denied_count > 0:
        console.print("[bold green]✓ Success: Sentinel Engine detected Sybil attack and blocked subsequent enrollments![/bold green]")
    else:
        console.print("[bold red]✗ Failure: Sybil attack was not throttled.[/bold red]")

async def test_connection_flood(client, base_url):
    # Send 55 rapid connections within 1 second to trigger CONN_FLOOD_LIMIT (50)
    console.print("Sending 55 rapid requests to trigger connection flood...")
    entity_id = f"agent-flood-{secrets.token_hex(4)}"
    
    tasks = []
    for i in range(55):
        payload = {
            "entity_id": entity_id,
            "name": "flooder",
            "version": "1.0.0",
            "intent": "Relay telemetry data",
            "source_ip": "10.0.0.150",
            "kem_public_key": f"kem-pub-{secrets.token_hex(20)}",
            "signature": secrets.token_hex(64)
        }
        tasks.append(client.post(f"{base_url}/api/enroll", json=payload))
        
    responses = await asyncio.gather(*tasks, return_exceptions=True)
    denied_count = sum(1 for r in responses if not isinstance(r, Exception) and r.status_code == 403)
    console.print(f"[bold]Blocked connections:[/bold] {denied_count} / 55")
    if denied_count > 0:
        console.print("[bold green]✓ Success: Sentinel Engine detected and blocked connection flood![/bold green]")
    else:
        console.print("[bold red]✗ Failure: Flood was not throttled.[/bold red]")

async def test_sql_injection(client, base_url):
    entity_id = f"agent-sqli-{secrets.token_hex(4)}"
    payload = {
        "entity_id": entity_id,
        "name": "malicious-actor",
        "version": "1.0.0",
        "intent": "Relay telemetry'; DROP TABLE sessions; --",
        "source_ip": "192.168.1.200",
        "kem_public_key": f"kem-pub-{secrets.token_hex(20)}",
        "signature": secrets.token_hex(64)
    }
    
    resp = await client.post(f"{base_url}/api/enroll", json=payload)
    if resp.status_code == 403:
        data = resp.json().get("detail", {})
        console.print("[bold green]✓ Success: SQL Injection intent blocked by Hybrid Trust Engine![/bold green]")
        console.print(f"  [bold]Verdict:[/bold] DENIED | [bold]Reason:[/bold] {data.get('reason')} | [bold]Confidence:[/bold] {data.get('confidence')}")
    else:
        console.print(f"[bold red]✗ Failure: SQL Injection intent was ALLOWED (HTTP {resp.status_code})[/bold red]")

async def test_pq_downgrade(client, base_url):
    entity_id = f"agent-downgrade-{secrets.token_hex(4)}"
    # Classical-only enrollment (no KEM key)
    payload = {
        "entity_id": entity_id,
        "name": "classical-sensor",
        "version": "1.0.0",
        "intent": "Relay telemetery data",
        "source_ip": "192.168.1.222",
        "kem_public_key": None,  # Downgrade attempt!
        "signature": secrets.token_hex(64)
    }
    
    resp = await client.post(f"{base_url}/api/enroll", json=payload)
    if resp.status_code == 403:
        data = resp.json().get("detail", {})
        console.print("[bold green]✓ Success: Classical-only session blocked. Post-Quantum enforcement active![/bold green]")
        console.print(f"  [bold]Refusal Reason:[/bold] {data.get('reason')}")
    else:
        console.print(f"[bold red]✗ Failure: Classical-only session was incorrectly permitted (HTTP {resp.status_code})[/bold red]")

async def test_handshake_pq_downgrade(client, base_url):
    entity_id = f"agent-hs-downgrade-{secrets.token_hex(4)}"
    # Classical-only handshake phase 2 (no KEM ciphertext)
    payload = {
        "session_id": str(uuid.uuid4()),
        "entity_id": entity_id,
        "phase": 2,
        "kem_ciphertext": None, # Downgrade attempt!
        "signature": secrets.token_hex(64)
    }
    
    resp = await client.post(f"{base_url}/api/handshake", json=payload)
    if resp.status_code == 403:
        data = resp.json().get("detail", {})
        console.print("[bold green]✓ Success: Handshake classical downgrade blocked. Post-Quantum enforcement active![/bold green]")
        console.print(f"  [bold]Refusal Reason:[/bold] {data.get('reason')}")
    else:
        console.print(f"[bold red]✗ Failure: Handshake classical downgrade was permitted (HTTP {resp.status_code})[/bold red]")

async def main():
    base_url = "http://localhost:3000"
    console.print(Panel.fit("[bold red]Kelan Security — Multi-Scenario Attack Simulation Suite[/bold red]", border_style="red"))
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        # Check server health first
        try:
            health_resp = await client.get(f"{base_url}/api/health")
            if health_resp.status_code != 200:
                console.print(f"[bold red]✗ FastAPI Server at {base_url} is not healthy![/bold red]")
                sys.exit(1)
        except Exception:
            console.print(f"[bold red]✗ FastAPI Server is not running at {base_url}! Run 'python scripts/start_server.py' first.[/bold red]")
            sys.exit(1)
            
        console.print("[bold green]✓ Connected to Kelan FastAPI Server![/bold green]\n")
        
        # 1. Clean Enrollment
        await run_scenario("Clean Enrollment", "Normal authenticated agent with valid intents and PQ keys", 
                           lambda: test_clean_enroll(client, base_url))
                           
        # 2. Sybil Attack
        await run_scenario("Sybil Attack", "Flooding /api/enroll to compromise entity identification rates",
                           lambda: test_sybil_attack(client, base_url))
                           
        # 3. Connection Flood
        await run_scenario("Connection Flood", "High-frequency requests to exhaust network buffers",
                           lambda: test_connection_flood(client, base_url))
                           
        # 4. SQL Injection Intent Detection
        await run_scenario("Malicious Intent (SQL Injection)", "Agent sending adversarial intent to compromise backend database",
                           lambda: test_sql_injection(client, base_url))
                           
        # 5. Post-Quantum Downgrade (Enrollment)
        await run_scenario("Classical-Only Enrollment Downgrade", "Agent attempting to skip ML-KEM-768 public key registration",
                           lambda: test_pq_downgrade(client, base_url))
                           
        # 6. Post-Quantum Downgrade (Handshake)
        await run_scenario("Classical-Only Handshake Downgrade", "Agent attempting classical session key exchange in Handshake Phase 2",
                           lambda: test_handshake_pq_downgrade(client, base_url))

if __name__ == "__main__":
    asyncio.run(main())
