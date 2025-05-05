import threading
import time
from rich.live import Live
from rich.table import Table

NUM_TASKS = 100
START_DELAY = 1      # delay 1s giữa mỗi task
TASK_DURATION = 5    # mỗi task chạy 5s

task_status = {f"Task {i+1:03}": "Waiting" for i in range(NUM_TASKS)}
lock = threading.Lock()

def generate_table():
    table = Table(title="Task Status (Running/Waiting only)")
    table.add_column("Task")
    table.add_column("Status")
    for task, status in task_status.items():
        if status != "Done":  # hide finished tasks
            table.add_row(task, status)
    return table

def run_task(task_name):
    with lock:
        task_status[task_name] = "Running"
    time.sleep(TASK_DURATION)
    with lock:
        task_status[task_name] = "Done"

def schedule_tasks():
    for i in range(NUM_TASKS):
        task_name = f"Task {i+1:03}"
        threading.Thread(target=run_task, args=(task_name,), daemon=True).start()
        time.sleep(START_DELAY)

# Start the display and task scheduler
with Live(generate_table(), refresh_per_second=5) as live:
    scheduler_thread = threading.Thread(target=schedule_tasks, daemon=True)
    scheduler_thread.start()

    # Continuously update table until all tasks are done
    while any(status != "Done" for status in task_status.values()):
        time.sleep(0.2)
        with lock:
            live.update(generate_table())
