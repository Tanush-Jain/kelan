import sys
import click
import httpx
import uuid
import secrets
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent))


console = Console()

@click.command()
@click.option("--server", default="http://localhost:3000", help="FastAPI Server URL")
@click.option("--entity-id", default=lambda: f"agent-{uuid.uuid4().hex[:8]}", help="Unique identifier of the entity")
@click.option("--name", default="kelan-sensor-cli", help="Human-readable name of the entity")
@click.option("--version", default="3.0.0", help="Software version of the entity")
@click.option("--intent", default="Establish secure AITP session to relay telemetry data", help="Intent statement for AI evaluation")
@click.option("--source-ip", default="127.0.0.1", help="Source IP address")
@click.option("--disable-pq", is_flag=True, help="Disable sending ML-KEM-768 public key")
@click.option("--disable-sig", is_flag=True, help="Disable sending signature")
def enroll(server, entity_id, name, version, intent, source_ip, disable_pq, disable_sig):
    """Kelan Security — CLI client to enroll an entity into the AITP security environment."""
    console.print(Panel.fit("[bold green]Kelan Security AITP — Entity Enrollment Client[/bold green]", border_style="green"))
    
    # Generate cryptographic parameters
    kem_key = None if disable_pq else f"kem-pub-{secrets.token_hex(48)}"
    signature = None if disable_sig else secrets.token_hex(64)
    
    payload = {
        "entity_id": entity_id,
        "name": name,
        "version": version,
        "intent": intent,
        "source_ip": source_ip,
        "kem_public_key": kem_key,
        "signature": signature
    }
    
    # Show parameters table
    table = Table(title="Enrollment Parameters")
    table.add_column("Parameter", style="cyan")
    table.add_column("Value", style="magenta")
    
    for k, v in payload.items():
        val = str(v)
        if len(val) > 40:
            val = val[:37] + "..."
        table.add_row(k, val)
        
    console.print(table)
    
    endpoint = f"{server.rstrip('/')}/api/enroll"
    console.print(f"Sending enrollment request to [bold cyan]{endpoint}[/bold cyan]...")
    
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(endpoint, json=payload)
            
            if resp.status_code == 200:
                data = resp.json()
                console.print("\n[bold green]✓ Enrollment Accepted![/bold green]")
                
                result_table = Table(title="Response Data", border_style="green")
                result_table.add_column("Field", style="cyan")
                result_table.add_column("Value", style="green")
                for k, v in data.items():
                    result_table.add_row(k, str(v))
                console.print(result_table)
            else:
                console.print(f"\n[bold red]✗ Enrollment Denied / Server Error (HTTP {resp.status_code})[/bold red]")
                try:
                    detail = resp.json().get("detail", {})
                    if isinstance(detail, dict):
                        console.print(Panel(
                            f"[bold]Error Code:[/bold] {detail.get('error', 'unknown')}\n"
                            f"[bold]Reason:[/bold] {detail.get('reason', 'no-reason')}\n"
                            f"[bold]Confidence:[/bold] {detail.get('confidence', 'N/A')}",
                            title="Server Security Refusal",
                            border_style="red"
                        ))
                    else:
                        console.print(f"Detail: {detail}")
                except Exception:
                    console.print(f"Raw Response: {resp.text}")
                    
    except Exception as e:
        console.print(f"\n[bold red]✗ Connection Error: Could not connect to FastAPI server at {server}[/bold red]")
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    enroll()
