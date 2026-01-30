from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from ..database import Base

class TaskStatus(enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class Severity(enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    address = Column(String, unique=True, index=True)
    target_type = Column(String)  # url, ip, domain
    os = Column(String, nullable=True)
    risk_level = Column(String, default="unknown")
    last_scanned_at = Column(DateTime, default=datetime.utcnow)
    
    tasks = relationship("ScanTask", back_populates="target")

class ScanTask(Base):
    __tablename__ = "scan_tasks"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    status = Column(SQLEnum(TaskStatus), default=TaskStatus.PENDING)
    scan_type = Column(String)  # quick, comprehensive, stealth
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    
    target = relationship("Target", back_populates="tasks")
    vulnerabilities = relationship("Vulnerability", back_populates="task")
    reports = relationship("Report", back_populates="task")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(Integer, ForeignKey("scan_tasks.id"))
    name = Column(String, index=True)
    severity = Column(SQLEnum(Severity), default=Severity.INFO)
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    tool_name = Column(String)
    raw_output = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    task = relationship("ScanTask", back_populates="vulnerabilities")

class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(Integer, ForeignKey("scan_tasks.id"))
    title = Column(String)
    content = Column(Text)  # JSON or Markdown
    created_at = Column(DateTime, default=datetime.utcnow)
    
    task = relationship("ScanTask", back_populates="reports")

