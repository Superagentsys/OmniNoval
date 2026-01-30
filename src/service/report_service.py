from sqlalchemy.orm import Session
from ..db.models import Target, ScanTask, Vulnerability, Report, TaskStatus, Severity
from datetime import datetime
from typing import List, Dict, Any

class ScanService:
    @staticmethod
    def create_target(db: Session, address: str, target_type: str):
        target = db.query(Target).filter(Target.address == address).first()
        if not target:
            target = Target(address=address, target_type=target_type)
            db.add(target)
            db.commit()
            db.refresh(target)
        return target

    @staticmethod
    def create_task(db: Session, target_id: int, scan_type: str):
        task = ScanTask(target_id=target_id, scan_type=scan_type, status=TaskStatus.RUNNING)
        db.add(task)
        db.commit()
        db.refresh(task)
        return task

    @staticmethod
    def update_task_status(db: Session, task_id: int, status: TaskStatus):
        task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if task:
            task.status = status
            if status in [TaskStatus.COMPLETED, TaskStatus.FAILED]:
                task.end_time = datetime.utcnow()
            db.commit()
        return task

    @staticmethod
    def add_vulnerability(db: Session, task_id: int, vul_data: Dict[str, Any]):
        vulnerability = Vulnerability(
            task_id=task_id,
            name=vul_data.get("name"),
            severity=vul_data.get("severity", Severity.INFO),
            description=vul_data.get("description"),
            remediation=vul_data.get("remediation"),
            tool_name=vul_data.get("tool_name"),
            raw_output=vul_data.get("raw_output")
        )
        db.add(vulnerability)
        db.commit()
        return vulnerability

class ReportService:
    @staticmethod
    def generate_report(db: Session, task_id: int):
        task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if not task:
            return None
        
        vulnerabilities = db.query(Vulnerability).filter(Vulnerability.task_id == task_id).all()
        
        # Simple report content generation
        report_content = {
            "target": task.target.address,
            "scan_type": task.scan_type,
            "start_time": task.start_time.isoformat(),
            "end_time": task.end_time.isoformat() if task.end_time else None,
            "vulnerabilities_count": len(vulnerabilities),
            "vulnerabilities": [
                {
                    "name": v.name,
                    "severity": v.severity.value,
                    "description": v.description,
                    "tool": v.tool_name
                } for v in vulnerabilities
            ]
        }
        
        report = Report(
            task_id=task_id,
            title=f"Security Scan Report for {task.target.address}",
            content=str(report_content)
        )
        db.add(report)
        db.commit()
        db.refresh(report)
        return report

    @staticmethod
    def get_statistics(db: Session):
        total_targets = db.query(Target).count()
        total_tasks = db.query(ScanTask).count()
        total_vulnerabilities = db.query(Vulnerability).count()
        
        severity_counts = {
            "critical": db.query(Vulnerability).filter(Vulnerability.severity == Severity.CRITICAL).count(),
            "high": db.query(Vulnerability).filter(Vulnerability.severity == Severity.HIGH).count(),
            "medium": db.query(Vulnerability).filter(Vulnerability.severity == Severity.MEDIUM).count(),
            "low": db.query(Vulnerability).filter(Vulnerability.severity == Severity.LOW).count(),
            "info": db.query(Vulnerability).filter(Vulnerability.severity == Severity.INFO).count(),
        }
        
        return {
            "total_targets": total_targets,
            "total_tasks": total_tasks,
            "total_vulnerabilities": total_vulnerabilities,
            "severity_distribution": severity_counts
        }

