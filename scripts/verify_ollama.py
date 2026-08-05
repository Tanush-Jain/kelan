import sys
import asyncio
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent))

from kelan.config import get_settings
from kelan.ai.ollama_client import OllamaClient

console = Console()

async def main():
    settings = get_settings()
    console.print(Panel.fit("[bold blue]Kelan Security — Ollama Integration Verifier[/bold blue]", border_style="blue"))
    
    console.print(f"Connecting to Ollama endpoint: [bold cyan]{settings.ollama_endpoint}[/bold cyan]...")
    client = OllamaClient(
        endpoint=settings.ollama_endpoint,
        model=settings.ollama_model,
        timeout=10
    )
    
    connected = await client.ping()
    if not connected:
        console.print("[bold red]✗ Failure: Could not reach Ollama! Is it running?[/bold red]")
        console.print("[yellow]Hint: Run 'ollama serve' in a separate terminal.[/yellow]")
        sys.exit(1)
        
    console.print("[bold green]✓ Success: Connected to Ollama![/bold green]")
    
    models = await client.list_models()
    console.print(f"Available local models: [green]{', '.join(models)}[/green]")
    
    target_model = settings.ollama_model
    model_found = target_model in models or any(m.startswith(target_model) for m in models)
    
    if model_found:
        console.print(f"[bold green]✓ Success: Target model '{target_model}' is available![/bold green]")
    else:
        console.print(f"[bold yellow]⚠ Warning: Target model '{target_model}' not found in local models list.[/bold yellow]")
        console.print(f"[yellow]You can pull the model via: 'ollama pull {target_model}'[/yellow]")
        
    # Test a quick dummy verdict
    console.print("\nTesting a dummy evaluation to verify inference pipeline...")
    dummy_session = {
        "entity_id": "test-verifier",
        "intent": "Verify ollama connection and inference correctness",
        "name": "verifier",
        "version": "1.0",
        "source_ip": "127.0.0.1",
        "anomalies": {},
        "has_kem_key": True,
        "has_signature": True,
        "timestamp": "2026-05-31T12:00:00Z"
    }
    
    try:
        verdict = await client.evaluate(dummy_session)
        console.print("[bold green]✓ Inference Success![/bold green]")
        console.print(Panel(
            f"[bold]Verdict:[/bold] {verdict.verdict.value}\n"
            f"[bold]Confidence:[/bold] {verdict.confidence}\n"
            f"[bold]Reason:[/bold] {verdict.reason}",
            title="AI Verdict Response",
            border_style="green"
        ))
    except Exception as e:
        console.print(f"[bold red]✗ Inference Failed: {e}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
