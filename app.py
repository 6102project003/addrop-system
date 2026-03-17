import os
import json
import boto3
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from functools import wraps
from datetime import datetime
import uuid

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # 改做安全嘅 key

# AWS 設定
dynamodb = boto3.resource('dynamodb', region_name='ap-east-1')
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
        
        # Demo 登入（正式應用應該 check DynamoDB）
        if user_id == 'admin' and password == 'admin123':
            session['user_id'] = 'admin1'
            session['user_name'] = 'Administrator'
            session['role'] = 'admin'
            return redirect(url_for('admin_courses'))
        elif user_id.startswith('s'):
            # 檢查學生是否存在
            response = students_table.get_item(Key={'studentId': user_id})
            if 'Item' in response:
                session['user_id'] = user_id
                session['user_name'] = response['Item'].get('name', 'Student')
                session['role'] = 'student'
                return redirect(url_for('student_courses'))
            else:
                # 自動註冊新學生（demo用）
                students_table.put_item(Item={
                    'studentId': user_id,
                    'name': f'Student {user_id}',
                    'enrolledCourses': []
                })
                session['user_id'] = user_id
                session['user_name'] = f'Student {user_id}'
                session['role'] = 'student'
                return redirect(url_for('student_courses'))
        
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
    
    # 拎全部課程
    response = courses_table.scan()
    courses = response.get('Items', [])
    
    # 拎學生已選課程
    student_resp = students_table.get_item(Key={'studentId': session['user_id']})
    student = student_resp.get('Item', {})
    enrolled = student.get('enrolledCourses', [])
    
    return render_template('student/courses.html', 
                         courses=courses, 
                         enrolled=enrolled,
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
