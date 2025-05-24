from celery import shared_task

@shared_task(name="run_scan_task")
def run_scan_task(scan_id: str, domain: str):
    print(f"Mock Scan: Received scan_id={scan_id}, domain={domain}")
    # Simulate work
    return f"Scan complete for {domain}"
