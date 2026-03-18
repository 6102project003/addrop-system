import os
import json
import boto3
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from functools import wraps
from datetime import datetime
import uuid
import bcrypt
import csv
import io
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # 改做安全嘅 key

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
            return redirect(url_for('student_dashboard'))
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
        
        # Admin login (special case - 可以之後都改用 hash)
        if user_id == 'admin' and password == 'admin123':
            session['user_id'] = 'admin1'
            session['user_name'] = 'Administrator'
            session['role'] = 'admin'
            return redirect(url_for('admin_courses'))
        
        # Student login
        elif user_id.startswith('s'):
            response = students_table.get_item(Key={'studentId': user_id})
            if 'Item' in response:
                student = response['Item']
                
                # Check 有冇 password_hash field
                stored_hash = student.get('password_hash')
                
                # 如果冇 hash，即係舊學生，用 plain text password check
                if not stored_hash:
                    # 用舊方法 check password (向後兼容)
                    old_password = student.get('password', user_id.replace('s', ''))
                    if password == old_password:
                        # 成功 login，即時 migrate 去 hash
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
                    # 有 hash，用 bcrypt check
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
    # 檢查課程
    course_resp = courses_table.get_item(Key={'courseId': course_id})
    if 'Item' not in course_resp:
        return jsonify({'error': 'Course not found'}), 404
    
    course = course_resp['Item']
    
    # 檢查名額
    if course['enrolled'] >= course['capacity']:
        # 加入候補
        waitlist = course.get('waitlist', [])
        if student_id not in waitlist:
            waitlist.append(student_id)
            courses_table.update_item(
                Key={'courseId': course_id},
                UpdateExpression='SET waitlist = :w',
                ExpressionAttributeValues={':w': waitlist}
            )
        return jsonify({'message': 'Course full, added to waitlist'})
    
    # 檢查時間衝突
    student_resp = students_table.get_item(Key={'studentId': student_id})
    student = student_resp.get('Item', {})
    enrolled_ids = student.get('enrolledCourses', [])
    
    for cid in enrolled_ids:
        c = courses_table.get_item(Key={'courseId': cid}).get('Item', {})
        if c.get('schedule') == course.get('schedule'):
            return jsonify({'error': 'Schedule conflict'}), 400
    
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
        ExpressionAttributeValues={':dec': 1}
    )
    
    # 從學生記錄移除
    student = students_table.get_item(Key={'studentId': student_id}).get('Item', {})
    enrolled = student.get('enrolledCourses', [])
    if course_id in enrolled:
        enrolled.remove(course_id)
        students_table.update_item(
            Key={'studentId': student_id},
            UpdateExpression='SET enrolledCourses = :e',
            ExpressionAttributeValues={':e': enrolled}
        )
    
    # 檢查候補
    course = courses_table.get_item(Key={'courseId': course_id}).get('Item', {})
    waitlist = course.get('waitlist', [])
    if waitlist:
        next_student = waitlist.pop(0)
        courses_table.update_item(
            Key={'courseId': course_id},
            UpdateExpression='SET waitlist = :w',
            ExpressionAttributeValues={':w': waitlist}
        )
        # 可以加通知
    
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
        'schedule': {
            'day': request.form.get('schedule_day', 'Mon'),
            'time': request.form.get('schedule_time', '09:00-12:00')
        },
        'waitlist': []
    }
    courses_table.put_item(Item=course)
    return redirect(url_for('admin_courses'))

@app.route('/admin/courses/update/<course_id>', methods=['POST'])
@login_required
@admin_required
def admin_update_course(course_id):
    update_expr = 'SET '
    expr_attrs = {}
    
    fields = ['name', 'credits', 'capacity', 'department', 'instructor']
    for field in fields:
        if field in request.form:
            update_expr += f'{field} = :{field}, '
            if field in ['credits', 'capacity']:
                expr_attrs[f':{field}'] = int(request.form[field])
            else:
                expr_attrs[f':{field}'] = request.form[field]
    
    # 處理 schedule
    if 'schedule_day' in request.form and 'schedule_time' in request.form:
        update_expr += 'schedule = :schedule, '
        expr_attrs[':schedule'] = {
            'day': request.form['schedule_day'],
            'time': request.form['schedule_time']
        }
    
    update_expr = update_expr.rstrip(', ')
    
    courses_table.update_item(
        Key={'courseId': course_id},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=expr_attrs
    )
    return redirect(url_for('admin_courses'))

@app.route('/admin/courses/delete/<course_id>')
@login_required
@admin_required
def admin_delete_course(course_id):
    courses_table.delete_item(Key={'courseId': course_id})
    return redirect(url_for('admin_courses'))

@app.route('/admin/stats')
@login_required
@admin_required
def admin_stats():
    return render_template('admin/stats.html', user=session)

@app.route('/admin/students')
@login_required
@admin_required
def admin_students():
    # Scan 全部 students
    response = students_table.scan()
    students = response.get('Items', [])
    
    # 為每個學生拎埋已選課程嘅詳細資料
    for student in students:
        enrolled_courses = []
        for course_id in student.get('enrolledCourses', []):
            course = courses_table.get_item(Key={'courseId': course_id}).get('Item', {})
            if course:
                enrolled_courses.append(course.get('name', course_id))
        student['enrolled_course_names'] = ', '.join(enrolled_courses) if enrolled_courses else 'None'
    
    return render_template('admin/students.html', students=students, user=session)

# ========== Admin Upload CSV Routes ==========
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
    
    for row in csv_reader:
        try:
            # 預期 CSV 欄位：
            # courseId,name,credits,capacity,department,instructor,day,time
            course = {
                'courseId': row['courseId'],
                'name': row['name'],
                'credits': int(row.get('credits', 3)),
                'capacity': int(row.get('capacity', 50)),
                'enrolled': 0,
                'department': row.get('department', ''),
                'instructor': row.get('instructor', ''),
                'schedule': {
                    'day': row.get('day', 'Mon'),
                    'time': row.get('time', '09:00-12:00')
                },
                'waitlist': []
            }
            
            # 插入 DynamoDB
            courses_table.put_item(Item=course)
            success_count += 1
            
        except Exception as e:
            print(f"Error inserting course: {e}")
            error_count += 1
    
    flash(f"Upload complete: {success_count} courses added, {error_count} errors", 'success')
    return redirect(url_for('admin_courses'))

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
    
    flash(f"Upload complete: {success_count} students added, {error_count} errors", 'success')
    return redirect(url_for('admin_students'))

# ========== Admin Student Management ==========
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
    flash(f'Student {student_id} added successfully', 'success')
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
        
        return jsonify({'message': f'Password reset to {new_password}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/student/<student_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_student(student_id):
    try:
        # 首先 delete 學生所有 enrollments
        enrollments = enrollments_table.scan(
            FilterExpression='studentId = :sid',
            ExpressionAttributeValues={':sid': student_id}
        ).get('Items', [])
        
        for enrollment in enrollments:
            enrollments_table.delete_item(Key={'enrollmentId': enrollment['enrollmentId']})
        
        # 然後 delete 學生本身
        students_table.delete_item(Key={'studentId': student_id})
        
        return jsonify({'message': 'Student deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ========== Student Change Password ==========
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

def enroll_course(student_id, course_id):
    # 檢查課程是否存在
    course_resp = courses_table.get_item(Key={'courseId': course_id})
    if 'Item' not in course_resp:
        return jsonify({'error': 'Course not found'}), 404
    
    course = course_resp['Item']
    
    # 檢查名額
    if course['enrolled'] >= course['capacity']:
        # 加入候補
        waitlist = course.get('waitlist', [])
        if student_id not in waitlist:
            waitlist.append(student_id)
            courses_table.update_item(
                Key={'courseId': course_id},
                UpdateExpression='SET waitlist = :w',
                ExpressionAttributeValues={':w': waitlist}
            )
        return jsonify({'message': 'Course full, added to waitlist'})
    
    # ===== 時間衝突檢查 =====
    student_resp = students_table.get_item(Key={'studentId': student_id})
    student = student_resp.get('Item', {})
    enrolled_ids = student.get('enrolledCourses', [])
    
    # 拎新課程嘅時間
    new_day = course.get('schedule', {}).get('day')
    new_time = course.get('schedule', {}).get('time')
    
    # 如果新課程冇時間，就當冇衝突
    if not new_day or not new_time:
        return jsonify({'error': 'Course schedule not available'}), 400
    
    # 拆新課程嘅開始同結束時間
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
        
        # 如果唔同日子，就冇衝突
        if old_day != new_day:
            continue
            
        if not old_time:
            continue
            
        try:
            old_start, old_end = old_time.split('-')
        except:
            continue
        
        # 時間衝突檢查：
        # 新課程 start < 舊課程 end  AND 新課程 end > 舊課程 start
        if new_start < old_end and new_end > old_start:
            return jsonify({'error': f'Schedule conflict with {c.get("courseId")} - {c.get("name")}'}), 400
    
    # ===== 時間檢查完畢 =====
    
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

# ========== 統計 API（俾前端 chart.js 用）=========
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
