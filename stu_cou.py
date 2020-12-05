# -*- coding: utf-8 -*-
# @Time : 2020/9/7 10:04
# @Author : YHL <yanghelong@inspur.com>
# @File : stu_cou.py
# explain : description
from flask import Blueprint

from config.mysqlConifg import db

stu_cou_blu = Blueprint('stu_cou_blu', __name__, url_prefix='/stu_cou')

tb_student_course = db.Table('tb_student_course',
							 db.Column('student_id', db.Integer, db.ForeignKey('students.id')),
							 db.Column('course_id', db.Integer, db.ForeignKey('courses.id'))
							 )


class Student(db.Model):
	__tablename__ = "students"
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(64), unique=True)

	courses = db.relationship('Course', secondary=tb_student_course,
							  backref='student',
							  lazy='dynamic')


class Course(db.Model):
	__tablename__ = "courses"
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(64), unique=True)


@stu_cou_blu.route('/stu_cou')
def stu_cou():
	db.drop_all()
	db.create_all()

	# 添加测试数据

	stu1 = Student(name='张三')
	stu2 = Student(name='李四')
	stu3 = Student(name='王五')

	cou1 = Course(name='物理')
	cou2 = Course(name='化学')
	cou3 = Course(name='生物')

	stu1.courses = [cou2, cou3]
	stu2.courses = [cou2]
	stu3.courses = [cou1, cou2, cou3]

	db.session.add_all([stu1, stu2, stu2])
	db.session.add_all([cou1, cou2, cou3])

	db.session.commit()
	return 'SUCCESS'
