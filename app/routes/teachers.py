from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.audit.logger import get_client_ip, log_data_change
from app.auth.dependencies import require_role
from app.database import get_db
from app.models import Grade, Subject, User
from app.schemas import GradeCreate

router = APIRouter(prefix="/teachers", tags=["Teachers"])


@router.get("/students/{student_id}/grades")
def student_grades(student_id: int,
                   current_user: User = Depends(require_role("teacher", "admin")),
                   db: Session = Depends(get_db)):
    grades = db.query(Grade).filter(Grade.student_id == student_id).all()
    return {"student_id": student_id,
            "grades": [{"subject_id": g.subject_id, "grade": g.grade,
                        "comment": g.comment} for g in grades]}


@router.post("/grades", status_code=status.HTTP_201_CREATED)
def add_grade(request: Request, data: GradeCreate,
              current_user: User = Depends(require_role("teacher", "admin")),
              db: Session = Depends(get_db)):
    if db.get(User, data.student_id) is None or db.get(Subject, data.subject_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Студента або дисципліну не знайдено")

    grade = Grade(student_id=data.student_id, subject_id=data.subject_id,
                  grade=data.grade, comment=data.comment,
                  assigned_by=current_user.id)  # підзвітність: хто виставив
    db.add(grade)
    db.commit()
    db.refresh(grade)

    log_data_change(db, current_user, get_client_ip(request),
                    resource=f"grades.id={grade.id}", old=None,
                    new={"student_id": grade.student_id, "subject_id": grade.subject_id,
                         "grade": grade.grade},
                    endpoint="/teachers/grades")
    return {"id": grade.id, "grade": grade.grade, "comment": grade.comment,
            "assigned_by": current_user.username}
