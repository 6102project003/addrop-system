import os
import json
import boto3
import bcrypt
import csv
import io
import uuid
import logging
import requests
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # 改做安全嘅 key

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# AWS 設定
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
courses_table = dynamodb.Table('Courses')
students_table = dynamodb.Table('Students')
enrollments_table = dynamodb.Table('Enrollments')
admins_table = dynamodb.Table('Admins')

# ========== 登入裝飾器 ==========
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            return redirect(url_for('student_courses'))
        return f(*args, **kwargs)
    return decorated_function

# ========== 認證路由 ==========
@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_courses'))
        return redirect(url_for('student_courses'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form['user_id']
        password = request.form['password']
        
        # Admin login - 統一用 admin / admin123
        if user_id == 'admin':
            # Check if admin exists
            response = admins_table.get_item(Key={'adminId': 'admin'})
            admin = response.get('Item', {})
            
            if admin:
                # Admin exists - check hash
                stored_hash = admin.get('password_hash')
                if stored_hash and bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                    session['user_id'] = 'admin'
                    session['user_name'] = admin.get('name', 'Administrator')
                    session['role'] = 'admin'
                    logging.info(f"Admin logged in")
                    return redirect(url_for('admin_courses'))
                else:
                    return render_template('login.html', error='Invalid password')
            else:
                # First time login - create admin with hash
                if password == 'admin123':
                    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    admins_table.put_item(Item={
                        'adminId': 'admin',
                        'name': 'Administrator',
                        'password_hash': password_hash
                    })
                    session['user_id'] = 'admin'
                    session['user_name'] = 'Administrator'
                    session['role'] = 'admin'
                    logging.info(f"Admin logged in (first time)")
                    return redirect(url_for('admin_courses'))
                else:
                    return render_template('login.html', error='Invalid credentials')
        
        # Student login
        elif user_id.startswith('s'):
            response = students_table.get_item(Key={'studentId': user_id})
            if 'Item' in response:
                student = response['Item']
                
                stored_hash = student.get('password_hash')
                
                if not stored_hash:
                    old_password = student.get('password', user_id.replace('s', ''))
                    if password == old_password:
                        new_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                        students_table.update_item(
                            Key={'studentId': user_id},
                            UpdateExpression='SET password_hash = :h REMOVE password',
                            ExpressionAttributeValues={':h': new_hash}
                        )
                        session['user_id'] = user_id
                        session['user_name'] = student.get('name', f'Student {user_id}')
                        session['role'] = 'student'
                        return redirect(url_for('student_courses'))
                else:
                    if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                        session['user_id'] = user_id
                        session['user_name'] = student.get('name', f'Student {user_id}')
                        session['role'] = 'student'
                        return redirect(url_for('student_courses'))
            
            return render_template('login.html', error='Invalid credentials')
        
        return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')
    
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ========== 學生路由 ==========
@app.route('/student/courses')
@login_required
def student_courses():
    if session.get('role') != 'student':
        return redirect(url_for('admin_courses'))
    
    # 拎全部課程 (for dropdown)
    response = courses_table.scan()
    all_courses = response.get('Items', [])
    
    # 拎搜尋參數
    search_term = request.args.get('search', '').lower()
    selected_dept = request.args.get('department', '')
    
    # Filter courses
    filtered_courses = []
    for course in all_courses:
        # Department filter
        if selected_dept and course.get('department', '') != selected_dept:
            continue
        
        # Search filter
        if search_term:
            if (search_term in course.get('courseId', '').lower() or 
                search_term in course.get('name', '').lower()):
                filtered_courses.append(course)
        else:
            filtered_courses.append(course)
    
    # 拎學生已選課程
    student_resp = students_table.get_item(Key={'studentId': session['user_id']})
    student = student_resp.get('Item', {})
    enrolled = student.get('enrolledCourses', [])
    
    return render_template('student/courses.html', 
                         courses=filtered_courses,
                         all_courses=all_courses,
                         enrolled=enrolled,
                         search_term=search_term,
                         selected_dept=selected_dept,
                         user=session)

@app.route('/student/schedule')
@login_required
def student_schedule():
    if session.get('role') != 'student':
        return redirect(url_for('admin_courses'))
    
    # 拎學生已選課程詳細資料
    student_resp = students_table.get_item(Key={'studentId': session['user_id']})
    student = student_resp.get('Item', {})
    enrolled_ids = student.get('enrolledCourses', [])
    
    courses = []
    for cid in enrolled_ids:
        course = courses_table.get_item(Key={'courseId': cid}).get('Item', {})
        if course:
            courses.append(course)
    
    # 按時間排序
    courses.sort(key=lambda x: x.get('schedule', {}).get('time', ''))
    
    return render_template('student/schedule.html', 
                         courses=courses,
                         user=session)

# ========== 學生 Change Password ==========
@app.route('/student/change-password', methods=['GET', 'POST'])
@login_required
def student_change_password():
    if session.get('role') != 'student':
        return redirect(url_for('admin_courses'))
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('New password and confirm password do not match', 'error')
            return redirect(url_for('student_change_password'))
        
        response = students_table.get_item(Key={'studentId': session['user_id']})
        student = response.get('Item', {})
        
        stored_hash = student.get('password_hash')
        
        # 如果冇 hash，用舊方法 check
        if not stored_hash:
            old_password = student.get('password', session['user_id'].replace('s', ''))
            if current_password != old_password:
                flash('Current password is incorrect', 'error')
                return redirect(url_for('student_change_password'))
        else:
            if not bcrypt.checkpw(current_password.encode('utf-8'), stored_hash.encode('utf-8')):
                flash('Current password is incorrect', 'error')
                return redirect(url_for('student_change_password'))
        
        # Hash 新密碼
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        students_table.update_item(
            Key={'studentId': session['user_id']},
            UpdateExpression='SET password_hash = :p',
            ExpressionAttributeValues={':p': new_password_hash}
        )
        
        flash('Password changed successfully', 'success')
        return redirect(url_for('student_courses'))
    
    return render_template('student/change_password.html', user=session)

# ========== 學生 API（加退選）=========
@app.route('/api/enroll', methods=['POST'])
@login_required
def api_enroll():
    data = request.get_json()
    student_id = session['user_id']
    course_id = data['courseId']
    action = data.get('action', 'enroll')
    
    if action == 'enroll':
        return enroll_course(student_id, course_id)
    else:
        return drop_course(student_id, course_id)

def enroll_course(student_id, course_id):
    # 檢查課程是否存在
    course_resp = courses_table.get_item(Key={'courseId': course_id})
    if 'Item' not in course_resp:
        return jsonify({'error': 'Course not found'}), 404
    
    course = course_resp['Item']
    
    # 檢查名額 - 直接返回 error，唔加 waitlist
    if course['enrolled'] >= course['capacity']:
        return jsonify({'error': 'Course is full'}), 400
    
    # ===== 時間衝突檢查 =====
    student_resp = students_table.get_item(Key={'studentId': student_id})
    student = student_resp.get('Item', {})
    enrolled_ids = student.get('enrolledCourses', [])
    
    # 拎新課程嘅時間
    new_day = course.get('schedule', {}).get('day')
    new_time = course.get('schedule', {}).get('time')
    
    if not new_day or not new_time:
        return jsonify({'error': 'Course schedule not available'}), 400
    
    try:
        new_start, new_end = new_time.split('-')
    except:
        return jsonify({'error': 'Invalid course time format'}), 400
    
    # Check 每一科已選課程
    for cid in enrolled_ids:
        c = courses_table.get_item(Key={'courseId': cid}).get('Item', {})
        if not c:
            continue
            
        old_day = c.get('schedule', {}).get('day')
        old_time = c.get('schedule', {}).get('time')
        
        if old_day != new_day:
            continue
            
        if not old_time:
            continue
            
        try:
            old_start, old_end = old_time.split('-')
        except:
            continue
        
        if new_start < old_end and new_end > old_start:
            return jsonify({'error': f'Schedule conflict with {c.get("courseId")} - {c.get("name")}'}), 400
    
    # 加選
    enrollment_id = str(uuid.uuid4())
    enrollments_table.put_item(Item={
        'enrollmentId': enrollment_id,
        'studentId': student_id,
        'courseId': course_id,
        'timestamp': datetime.utcnow().isoformat(),
        'status': 'enrolled'
    })
    
    # 更新課程人數
    courses_table.update_item(
        Key={'courseId': course_id},
        UpdateExpression='SET enrolled = enrolled + :inc',
        ExpressionAttributeValues={':inc': 1}
    )
    
    # 更新學生記錄
    students_table.update_item(
        Key={'studentId': student_id},
        UpdateExpression='SET enrolledCourses = list_append(if_not_exists(enrolledCourses, :empty), :course)',
        ExpressionAttributeValues={
            ':course': [course_id],
            ':empty': []
        }
    )
    
    return jsonify({'message': 'Enrollment successful'})

def drop_course(student_id, course_id):
    # 檢查學生是否存在
    student_resp = students_table.get_item(Key={'studentId': student_id})
    student = student_resp.get('Item', {})
    if not student:
        return jsonify({'error': 'Student not found'}), 404
    
    # 檢查學生係咪真係有報讀呢科
    enrolled = student.get('enrolledCourses', [])
    if course_id not in enrolled:
        return jsonify({'error': 'You are not enrolled in this course'}), 400
    
    # 檢查課程是否存在
    course_resp = courses_table.get_item(Key={'courseId': course_id})
    course = course_resp.get('Item', {})
    if not course:
        return jsonify({'error': 'Course not found'}), 404
    
    # 檢查課程人數
    if course.get('enrolled', 0) <= 0:
        return jsonify({'error': 'Course enrollment count error'}), 500
    
    # 刪除 enrollment record
    enrollments = enrollments_table.scan(
        FilterExpression='studentId = :sid AND courseId = :cid',
        ExpressionAttributeValues={':sid': student_id, ':cid': course_id}
    ).get('Items', [])
    
    for e in enrollments:
        enrollments_table.delete_item(Key={'enrollmentId': e['enrollmentId']})
    
    # 減少課程人數
    courses_table.update_item(
        Key={'courseId': course_id},
        UpdateExpression='SET enrolled = enrolled - :dec',
        ConditionExpression='enrolled > :zero',
        ExpressionAttributeValues={':dec': 1, ':zero': 0}
    )
    
    # 從學生記錄移除
    enrolled.remove(course_id)
    students_table.update_item(
        Key={'studentId': student_id},
        UpdateExpression='SET enrolledCourses = :e',
        ExpressionAttributeValues={':e': enrolled}
    )
    
    return jsonify({'message': 'Drop successful'})

# ========== 管理員路由 ==========
@app.route('/admin/courses')
@login_required
@admin_required
def admin_courses():
    response = courses_table.scan()
    courses = response.get('Items', [])
    return render_template('admin/courses.html', courses=courses, user=session)

@app.route('/admin/courses/add', methods=['POST'])
@login_required
@admin_required
def admin_add_course():
    course = {
        'courseId': request.form['courseId'],
        'name': request.form['name'],
        'credits': int(request.form.get('credits', 3)),
        'capacity': int(request.form.get('capacity', 50)),
        'enrolled': 0,
        'department': request.form.get('department', ''),
        'instructor': request.form.get('instructor', ''),
        'location': request.form.get('location', 'TBA'),  # 加呢行
        'schedule': {
            'day': request.form.get('schedule_day', 'Mon'),
            'time': request.form.get('schedule_time', '09:00-12:00')
        },
        'waitlist': []
    }
    courses_table.put_item(Item=course)
    logging.info(f"Admin added course {course['courseId']}")
    flash(f'Course {course["courseId"]} added successfully', 'success')
    return redirect(url_for('admin_courses'))

@app.route('/admin/course/<course_id>/update-capacity', methods=['POST'])
@login_required
@admin_required
def admin_update_course_capacity(course_id):
    try:
        new_capacity = int(request.form['capacity'])
        
        # Get current course to check enrolled <= new capacity
        response = courses_table.get_item(Key={'courseId': course_id})
        if 'Item' not in response:
            flash('Course not found', 'error')
            return redirect(url_for('admin_courses'))
        
        course = response['Item']
        current_enrolled = course.get('enrolled', 0)
        
        if new_capacity < current_enrolled:
            flash(f'Cannot set capacity below current enrolled students ({current_enrolled})', 'error')
            return redirect(url_for('admin_courses'))
        
        # Update capacity - FIXED VERSION
        courses_table.update_item(
            Key={'courseId': course_id},
            UpdateExpression='SET #cap = :c',
            ExpressionAttributeNames={
                '#cap': 'capacity'
            },
            ExpressionAttributeValues={':c': new_capacity}
        )
        
        logging.info(f"Admin updated capacity for {course_id} to {new_capacity}")
        flash(f'Capacity updated successfully for {course_id}', 'success')
        
    except Exception as e:
        flash(f'Error updating capacity: {str(e)}', 'error')
    
    return redirect(url_for('admin_courses'))

@app.route('/admin/courses/bulk-delete', methods=['POST'])
@login_required
@admin_required
def admin_bulk_delete_courses():
    course_ids = request.form.getlist('course_ids')
    
    if not course_ids:
        flash('No courses selected', 'error')
        return redirect(url_for('admin_courses'))
    
    success_count = 0
    error_count = 0
    
    for course_id in course_ids:
        try:
            # Check if course has enrolled students
            course = courses_table.get_item(Key={'courseId': course_id}).get('Item', {})
            if course.get('enrolled', 0) > 0:
                error_count += 1
                continue
            
            # Delete the course
            courses_table.delete_item(Key={'courseId': course_id})
            success_count += 1
            
        except Exception as e:
            print(f"Error deleting course {course_id}: {e}")
            error_count += 1
    
    flash(f"Successfully deleted {success_count} courses" + (f", {error_count} skipped (has enrolled students)" if error_count else ""), 'success')
    return redirect(url_for('admin_courses'))

@app.route('/api/course/<course_id>/students', methods=['GET'])
@login_required
@admin_required
def api_course_students(course_id):
    try:
        # 拎課程資料
        course_resp = courses_table.get_item(Key={'courseId': course_id})
        course = course_resp.get('Item', {})
        
        if not course:
            return jsonify({'error': 'Course not found'}), 404
        
        # 搵所有報讀呢個課程嘅學生
        enrollments = enrollments_table.scan(
            FilterExpression='courseId = :cid',
            ExpressionAttributeValues={':cid': course_id}
        ).get('Items', [])
        
        students = []
        for enrollment in enrollments:
            student_id = enrollment['studentId']
            student = students_table.get_item(Key={'studentId': student_id}).get('Item', {})
            if student:
                students.append({
                    'studentId': student_id,
                    'name': student.get('name', 'Unknown'),
                    'enrolledDate': enrollment.get('timestamp', 'N/A').split('T')[0] if enrollment.get('timestamp') else 'N/A'
                })
        
        # 加返 instructor, schedule, location
        schedule = f"{course.get('schedule', {}).get('day', '')} {course.get('schedule', {}).get('time', '')}"
        
        return jsonify({
            'courseId': course_id,
            'courseName': course.get('name', ''),
            'instructor': course.get('instructor', 'TBA'),
            'schedule': schedule.strip(),
            'location': course.get('location', 'TBA'),
            'enrolled': course.get('enrolled', 0),
            'capacity': course.get('capacity', 0),
            'students': students
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/courses/delete/<course_id>')
@login_required
@admin_required
def admin_delete_course(course_id):
    courses_table.delete_item(Key={'courseId': course_id})
    logging.info(f"Admin deleted course {course_id}")
    flash(f'Course {course_id} deleted successfully', 'success')
    return redirect(url_for('admin_courses'))

@app.route('/admin/students')
@login_required
@admin_required
def admin_students():
    # Scan 全部 students
    response = students_table.scan()
    students = response.get('Items', [])
    
    # 為每個學生計 enrolled_count
    for student in students:
        enrolled_ids = student.get('enrolledCourses', [])
        student['enrolled_count'] = len(enrolled_ids)
    
    return render_template('admin/students.html', students=students, user=session)

@app.route('/admin/student/add', methods=['POST'])
@login_required
@admin_required
def admin_add_student():
    student_id = request.form['studentId']
    name = request.form['name']
    password = request.form.get('password', '')
    
    # 如果冇俾 password，用 studentId 數字
    if not password:
        password = student_id.replace('s', '')
    
    # Hash 密碼
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # 檢查學生是否已經存在
    response = students_table.get_item(Key={'studentId': student_id})
    if 'Item' in response:
        flash(f'Student {student_id} already exists', 'error')
        return redirect(url_for('admin_students'))
    
    # 新增學生 (用 password_hash 代替 password)
    student = {
        'studentId': student_id,
        'name': name,
        'password_hash': password_hash,
        'enrolledCourses': []
    }
    
    students_table.put_item(Item=student)
    logging.info(f"Admin added student {student_id}")
    flash(f'Student {student_id} added successfully', 'success')
    return redirect(url_for('admin_students'))

@app.route('/admin/upload/students', methods=['POST'])
@login_required
@admin_required
def admin_upload_students():
    if 'file' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('admin_students'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('admin_students'))
    
    if not file.filename.endswith('.csv'):
        flash('Please upload a CSV file', 'error')
        return redirect(url_for('admin_students'))
    
    # Read CSV file
    stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
    csv_reader = csv.DictReader(stream)
    
    success_count = 0
    error_count = 0
    
    for row in csv_reader:
        try:
            student_id = row['studentId']
            name = row['name']
            password = row.get('password', student_id.replace('s', ''))
            
            # Hash 密碼
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            student = {
                'studentId': student_id,
                'name': name,
                'password_hash': password_hash,
                'enrolledCourses': []
            }
            
            students_table.put_item(Item=student)
            success_count += 1
            
        except Exception as e:
            print(f"Error inserting student: {e}")
            error_count += 1
    
    logging.info(f"Admin uploaded {success_count} students, {error_count} errors")
    flash(f"Upload complete: {success_count} students added, {error_count} errors", 'success')
    return redirect(url_for('admin_students'))

@app.route('/admin/upload/courses', methods=['POST'])
@login_required
@admin_required
def admin_upload_courses():
    if 'file' not in request.files:
        flash('No file uploaded', 'error')
        return redirect(url_for('admin_courses'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('admin_courses'))
    
    if not file.filename.endswith('.csv'):
        flash('Please upload a CSV file', 'error')
        return redirect(url_for('admin_courses'))
    
    # Read CSV file
    stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
    csv_reader = csv.DictReader(stream)
    
    success_count = 0
    error_count = 0
    updated_count = 0
    skipped_count = 0
    
    for row in csv_reader:
        try:
            course_id = row['courseId']
            
            # Check if course already exists
            existing = courses_table.get_item(Key={'courseId': course_id}).get('Item')
            
            if existing:
                # Course exists - update only specific fields, preserve enrolled
                update_expr = 'SET #n = :n, credits = :credits, capacity = :capacity, '
                update_expr += 'department = :dept, instructor = :instructor, '
                update_expr += '#loc = :loc, schedule = :schedule'
                
                expr_attrs = {
                    ':n': row['name'],
                    ':credits': int(row.get('credits', 3)),
                    ':capacity': int(row.get('capacity', 50)),
                    ':dept': row.get('department', ''),
                    ':instructor': row.get('instructor', ''),
                    ':loc': row.get('location', 'TBA'),
                    ':schedule': {
                        'day': row.get('day', 'Mon'),
                        'time': row.get('time', '09:00-12:00')
                    }
                }
                
                expr_names = {
                    '#n': 'name',
                    '#loc': 'location'
                }
                
                courses_table.update_item(
                    Key={'courseId': course_id},
                    UpdateExpression=update_expr,
                    ExpressionAttributeNames=expr_names,
                    ExpressionAttributeValues=expr_attrs
                )
                updated_count += 1
                
            else:
                # New course - create with enrolled = 0
                course = {
                    'courseId': course_id,
                    'name': row['name'],
                    'credits': int(row.get('credits', 3)),
                    'capacity': int(row.get('capacity', 50)),
                    'enrolled': 0,
                    'department': row.get('department', ''),
                    'instructor': row.get('instructor', ''),
                    'location': row.get('location', 'TBA'),
                    'schedule': {
                        'day': row.get('day', 'Mon'),
                        'time': row.get('time', '09:00-12:00')
                    },
                    'waitlist': []
                }
                courses_table.put_item(Item=course)
                success_count += 1
            
        except Exception as e:
            print(f"Error processing course: {e}")
            error_count += 1
    
    msg = f"Upload complete: {success_count} new courses added, {updated_count} courses updated"
    if error_count:
        msg += f", {error_count} errors"
    
    logging.info(msg)
    flash(msg, 'success')
    return redirect(url_for('admin_courses'))

@app.route('/admin/students/bulk-delete', methods=['POST'])
@login_required
@admin_required
def admin_bulk_delete_students():
    student_ids = request.form.getlist('student_ids')
    
    if not student_ids:
        flash('No students selected', 'error')
        return redirect(url_for('admin_students'))
    
    success_count = 0
    error_count = 0
    
    for student_id in student_ids:
        try:
            # Delete all enrollments for this student
            enrollments = enrollments_table.scan(
                FilterExpression='studentId = :sid',
                ExpressionAttributeValues={':sid': student_id}
            ).get('Items', [])
            
            for enrollment in enrollments:
                enrollments_table.delete_item(Key={'enrollmentId': enrollment['enrollmentId']})
            
            # Delete the student
            students_table.delete_item(Key={'studentId': student_id})
            success_count += 1
            
        except Exception as e:
            print(f"Error deleting student {student_id}: {e}")
            error_count += 1
    
    logging.info(f"Admin bulk deleted {success_count} students, {error_count} errors")
    flash(f"Successfully deleted {success_count} students" + (f", {error_count} failed" if error_count else ""), 'success')
    return redirect(url_for('admin_students'))

@app.route('/admin/student/<student_id>/reset-password', methods=['POST'])
@login_required
@admin_required
def admin_reset_student_password(student_id):
    try:
        # 新 password = 學生ID 入面嘅數字部分
        new_password = student_id.replace('s', '')
        
        # Hash 新密碼
        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        students_table.update_item(
            Key={'studentId': student_id},
            UpdateExpression='SET password_hash = :p',
            ExpressionAttributeValues={':p': password_hash}
        )
        
        logging.info(f"Admin reset password for {student_id}")
        return jsonify({'message': f'Password reset to {new_password}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/student/<student_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_student(student_id):
    try:
        # Delete all enrollments for this student
        enrollments = enrollments_table.scan(
            FilterExpression='studentId = :sid',
            ExpressionAttributeValues={':sid': student_id}
        ).get('Items', [])
        
        for enrollment in enrollments:
            enrollments_table.delete_item(Key={'enrollmentId': enrollment['enrollmentId']})
        
        # Delete the student
        students_table.delete_item(Key={'studentId': student_id})
        
        logging.info(f"Admin deleted student {student_id}")
        return jsonify({'message': 'Student deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/stats')
@login_required
@admin_required
def admin_stats():
    # 拎全部課程
    response = courses_table.scan()
    courses = response.get('Items', [])
    
    # 按 courseId 排序
    courses.sort(key=lambda x: x.get('courseId', ''))
    
    return render_template('admin/stats.html', user=session, courses=courses)

@app.route('/api/student/<student_id>/courses', methods=['GET'])
@login_required
@admin_required
def api_student_courses(student_id):
    try:
        # 拎學生資料
        student_resp = students_table.get_item(Key={'studentId': student_id})
        student = student_resp.get('Item', {})
        
        if not student:
            return jsonify({'error': 'Student not found'}), 404
        
        # 拎已選課程 IDs
        enrolled_ids = student.get('enrolledCourses', [])
        
        # 拎課程詳細資料
        courses = []
        for cid in enrolled_ids:
            course = courses_table.get_item(Key={'courseId': cid}).get('Item', {})
            if course:
                courses.append({
                    'courseId': course.get('courseId'),
                    'name': course.get('name'),
                    'schedule': course.get('schedule'),
                    'location': course.get('location', 'TBA')
                })
        
        return jsonify({
            'studentId': student_id,
            'name': student.get('name', ''),
            'courses': courses
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ========== Admin Change Password ==========
@app.route('/admin/change-password', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('New password and confirm password do not match', 'error')
            return redirect(url_for('admin_change_password'))
        
        # Get admin record
        response = admins_table.get_item(Key={'adminId': 'admin'})
        admin = response.get('Item', {})
        
        if not admin:
            flash('Admin not found', 'error')
            return redirect(url_for('admin_change_password'))
        
        # Check current password
        stored_hash = admin.get('password_hash')
        if not stored_hash or not bcrypt.checkpw(current_password.encode('utf-8'), stored_hash.encode('utf-8')):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('admin_change_password'))
        
        # Update to new password
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        admins_table.update_item(
            Key={'adminId': 'admin'},
            UpdateExpression='SET password_hash = :p, #n = :name_val',
            ExpressionAttributeNames={'#n': 'name'},
            ExpressionAttributeValues={
                ':p': new_password_hash,
                ':name_val': 'Administrator'
            }
        )
        
        flash('Password changed successfully', 'success')
        return redirect(url_for('admin_courses'))
    
    return render_template('admin/change_password.html', user=session)

# ========== Semester Reset Functions ==========
@app.route('/admin/semester-reset')
@login_required
@admin_required
def admin_semester_reset():
    return render_template('admin/semester_reset.html', user=session)

@app.route('/admin/reset/enrollments', methods=['POST'])
@login_required
@admin_required
def admin_reset_enrollments():
    try:
        # 1. Delete all enrollments
        enrollments = enrollments_table.scan().get('Items', [])
        for enrollment in enrollments:
            enrollments_table.delete_item(Key={'enrollmentId': enrollment['enrollmentId']})
        
        # 2. Reset enrolled count in all courses to 0
        courses = courses_table.scan().get('Items', [])
        for course in courses:
            courses_table.update_item(
                Key={'courseId': course['courseId']},
                UpdateExpression='SET enrolled = :zero, waitlist = :empty',
                ExpressionAttributeValues={':zero': 0, ':empty': []}
            )
        
        # 3. Clear enrolledCourses from all students
        students = students_table.scan().get('Items', [])
        for student in students:
            students_table.update_item(
                Key={'studentId': student['studentId']},
                UpdateExpression='SET enrolledCourses = :empty',
                ExpressionAttributeValues={':empty': []}
            )
        
        flash('All enrollments cleared successfully', 'success')
        logging.info("Admin cleared all enrollments")
        
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('admin_semester_reset'))

@app.route('/admin/reset/courses', methods=['POST'])
@login_required
@admin_required
def admin_reset_courses():
    try:
        # 1. Delete all enrollments
        enrollments = enrollments_table.scan().get('Items', [])
        for enrollment in enrollments:
            enrollments_table.delete_item(Key={'enrollmentId': enrollment['enrollmentId']})
        
        # 2. Delete all courses
        courses = courses_table.scan().get('Items', [])
        for course in courses:
            courses_table.delete_item(Key={'courseId': course['courseId']})
        
        # 3. Clear enrolledCourses from all students
        students = students_table.scan().get('Items', [])
        for student in students:
            students_table.update_item(
                Key={'studentId': student['studentId']},
                UpdateExpression='SET enrolledCourses = :empty',
                ExpressionAttributeValues={':empty': []}
            )
        
        flash('All courses deleted and enrollments cleared', 'success')
        logging.info("Admin deleted all courses")
        
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('admin_semester_reset'))

@app.route('/admin/reset/students', methods=['POST'])
@login_required
@admin_required
def admin_reset_students():
    try:
        # 1. Delete all enrollments
        enrollments = enrollments_table.scan().get('Items', [])
        for enrollment in enrollments:
            enrollments_table.delete_item(Key={'enrollmentId': enrollment['enrollmentId']})
        
        # 2. Delete all students
        students = students_table.scan().get('Items', [])
        for student in students:
            students_table.delete_item(Key={'studentId': student['studentId']})
        
        # 3. Reset enrolled count in all courses to 0
        courses = courses_table.scan().get('Items', [])
        for course in courses:
            courses_table.update_item(
                Key={'courseId': course['courseId']},
                UpdateExpression='SET enrolled = :zero, waitlist = :empty',
                ExpressionAttributeValues={':zero': 0, ':empty': []}
            )
        
        flash('All students deleted and enrollments cleared', 'success')
        logging.info("Admin deleted all students")
        
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('admin_semester_reset'))

@app.route('/admin/reset/complete', methods=['POST'])
@login_required
@admin_required
def admin_reset_complete():
    try:
        # 1. Delete all enrollments
        enrollments = enrollments_table.scan().get('Items', [])
        for enrollment in enrollments:
            enrollments_table.delete_item(Key={'enrollmentId': enrollment['enrollmentId']})
        
        # 2. Delete all courses
        courses = courses_table.scan().get('Items', [])
        for course in courses:
            courses_table.delete_item(Key={'courseId': course['courseId']})
        
        # 3. Delete all students
        students = students_table.scan().get('Items', [])
        for student in students:
            students_table.delete_item(Key={'studentId': student['studentId']})
        
        flash('Complete reset: All enrollments, courses, and students deleted', 'success')
        logging.info("Admin performed complete system reset")
        
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    
    return redirect(url_for('admin_semester_reset'))

# ========== Backup & Recover Functions ==========
@app.route('/admin/backup', methods=['POST'])
@login_required
@admin_required
def admin_backup():
    try:
        # Get all data
        courses = courses_table.scan().get('Items', [])
        students = students_table.scan().get('Items', [])
        enrollments = enrollments_table.scan().get('Items', [])
        
        # Create backup data structure
        backup_data = {
            'backup_date': datetime.utcnow().isoformat(),
            'version': '1.0',
            'courses': courses,
            'students': students,
            'enrollments': enrollments
        }
        
        # Convert to JSON
        json_data = json.dumps(backup_data, indent=2, default=str)
        
        # Create response with file download
        from flask import make_response
        response = make_response(json_data)
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = f'attachment; filename=addrop_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        
        logging.info(f"Admin downloaded backup with {len(courses)} courses, {len(students)} students, {len(enrollments)} enrollments")
        return response
        
    except Exception as e:
        flash(f'Backup failed: {str(e)}', 'error')
        return redirect(url_for('admin_semester_reset'))

@app.route('/admin/recover', methods=['POST'])
@login_required
@admin_required
def admin_recover():
    try:
        if 'backup_file' not in request.files:
            flash('No file uploaded', 'error')
            return redirect(url_for('admin_semester_reset'))
        
        file = request.files['backup_file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('admin_semester_reset'))
        
        if not file.filename.endswith('.json'):
            flash('Please upload a JSON backup file', 'error')
            return redirect(url_for('admin_semester_reset'))
        
        # Read and parse JSON
        content = file.read().decode('utf-8')
        backup_data = json.loads(content)
        
        # Validate backup structure
        if 'courses' not in backup_data or 'students' not in backup_data or 'enrollments' not in backup_data:
            flash('Invalid backup file format', 'error')
            return redirect(url_for('admin_semester_reset'))
        
        # Clear existing data
        existing_courses = courses_table.scan().get('Items', [])
        for course in existing_courses:
            courses_table.delete_item(Key={'courseId': course['courseId']})
        
        existing_students = students_table.scan().get('Items', [])
        for student in existing_students:
            students_table.delete_item(Key={'studentId': student['studentId']})
        
        existing_enrollments = enrollments_table.scan().get('Items', [])
        for enrollment in existing_enrollments:
            enrollments_table.delete_item(Key={'enrollmentId': enrollment['enrollmentId']})
        
        # Restore courses (FIXED: convert string to int)
        for course in backup_data['courses']:
            capacity = course.get('capacity', 50)
            enrolled = course.get('enrolled', 0)
            credits = course.get('credits', 3)
            
            # Convert to int if they are strings
            if isinstance(capacity, str):
                capacity = int(capacity)
            if isinstance(enrolled, str):
                enrolled = int(enrolled)
            if isinstance(credits, str):
                credits = int(credits)
            
            clean_course = {
                'courseId': course['courseId'],
                'name': course['name'],
                'credits': credits,
                'capacity': capacity,
                'enrolled': enrolled,
                'department': course.get('department', ''),
                'instructor': course.get('instructor', ''),
                'location': course.get('location', 'TBA'),
                'schedule': course.get('schedule', {'day': 'Mon', 'time': '09:00-12:00'}),
                'waitlist': course.get('waitlist', [])
            }
            courses_table.put_item(Item=clean_course)
        
        # Restore students
        for student in backup_data['students']:
            clean_student = {
                'studentId': student['studentId'],
                'name': student['name'],
                'enrolledCourses': student.get('enrolledCourses', [])
            }
            if 'password_hash' in student:
                clean_student['password_hash'] = student['password_hash']
            students_table.put_item(Item=clean_student)
        
        # Restore enrollments
        for enrollment in backup_data['enrollments']:
            clean_enrollment = {
                'enrollmentId': enrollment['enrollmentId'],
                'studentId': enrollment['studentId'],
                'courseId': enrollment['courseId'],
                'timestamp': enrollment.get('timestamp', datetime.utcnow().isoformat()),
                'status': enrollment.get('status', 'enrolled')
            }
            enrollments_table.put_item(Item=clean_enrollment)
        
        flash(f'Recovery successful! Restored {len(backup_data["courses"])} courses, {len(backup_data["students"])} students, {len(backup_data["enrollments"])} enrollments', 'success')
        logging.info(f"Admin restored backup: {len(backup_data['courses'])} courses, {len(backup_data['students'])} students, {len(backup_data['enrollments'])} enrollments")
        
    except json.JSONDecodeError as e:
        flash(f'Invalid JSON file: {str(e)}', 'error')
    except Exception as e:
        flash(f'Recovery failed: {str(e)}', 'error')
        logging.error(f"Recovery error: {str(e)}")
    
    return redirect(url_for('admin_semester_reset'))

# ========== Free AI Chatbot (Hugging Face) ==========
HF_API_TOKEN = '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'  # 貼你嘅 token
HF_MODEL = 'microsoft/DialoGPT-small'  # 免費模型

@app.route('/api/chat', methods=['POST'])
@login_required
def api_chat():
    if session.get('role') != 'student':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    user_message = data.get('message', '')
    
    if not user_message:
        return jsonify({'error': 'No message provided'}), 400
    
    # 拎學生已選課程做 context
    student_resp = students_table.get_item(Key={'studentId': session['user_id']})
    student = student_resp.get('Item', {})
    enrolled_ids = student.get('enrolledCourses', [])
    
    courses = []
    for cid in enrolled_ids:
        course = courses_table.get_item(Key={'courseId': cid}).get('Item', {})
        if course:
            courses.append(f"{course['name']} ({course['courseId']})")
    
    enrolled_text = "You are currently enrolled in: " + ", ".join(courses) if courses else "You are not enrolled in any courses yet."
    
    # 構建 prompt
    prompt = f"""You are a helpful academic advisor. 
The student is asking: {user_message}
{enrolled_text}
Please give a friendly, helpful response about course recommendations. Keep it short and simple."""

    try:
        # Call Hugging Face Inference API
        headers = {
            'Authorization': f'Bearer {HF_API_TOKEN}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'inputs': prompt,
            'parameters': {
                'max_new_tokens': 150,
                'temperature': 0.7,
                'do_sample': True
            }
        }
        
        response = requests.post(
            f'https://api-inference.huggingface.co/models/{HF_MODEL}',
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            # 不同模型回傳格式唔同
            if isinstance(result, list) and len(result) > 0:
                if 'generated_text' in result[0]:
                    ai_message = result[0]['generated_text']
                else:
                    ai_message = str(result[0])
            else:
                ai_message = str(result)
            
            # 移除 prompt 本身
            if ai_message.startswith(prompt):
                ai_message = ai_message[len(prompt):].strip()
            
            # 如果太長，cut短
            if len(ai_message) > 500:
                ai_message = ai_message[:500] + "..."
            
            return jsonify({
                'message': ai_message,
                'status': 'success'
            })
        else:
            # API 失敗，返回錯誤
            return jsonify({
                'error': f'AI service unavailable (HTTP {response.status_code})',
                'status': 'error'
            }), 503
            
    except Exception as e:
        print(f"AI Error: {e}")
        return jsonify({
            'error': 'AI service unavailable',
            'status': 'error'
        }), 503

# ========== 統計 API ==========
@app.route('/api/stats/enrollment-by-dept')
@login_required
@admin_required
def api_stats_dept():
    courses = courses_table.scan().get('Items', [])
    dept_count = {}
    
    for c in courses:
        dept = c.get('department', 'Unknown')
        dept_count[dept] = dept_count.get(dept, 0) + c.get('enrolled', 0)
    
    result = [{'department': k, 'count': v} for k, v in dept_count.items()]
    return jsonify(result)

@app.route('/api/stats/popular-courses')
@login_required
@admin_required
def api_stats_popular():
    courses = courses_table.scan().get('Items', [])
    courses.sort(key=lambda x: x.get('enrolled', 0), reverse=True)
    top = courses[:10]
    
    result = [{
        'courseId': c['courseId'],
        'name': c['name'],
        'enrolled': c.get('enrolled', 0),
        'capacity': c.get('capacity', 0)
    } for c in top]
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
