from flask import Flask, render_template, request, jsonify
import os
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'sample_data'
app.config['ALLOWED_EXTENSIONS'] = {'json'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB文件上传限制

# ============================================
# 统一风险分析算法（与前端 analyzeRisk 完全对齐）
# 唯一真源：任何算法修改只改此函数 + 前端同一套逻辑
# ============================================

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def parse_date(date_str):
    if not date_str:
        return None
    # 优先用正则解析 yyyy-mm-dd 兼容各种分隔符
    parts = re.match(r'(\d{4})[^\d]*(\d{1,2})[^\d]*(\d{1,2})', str(date_str))
    if parts:
        try:
            return datetime(int(parts.group(1)), int(parts.group(2)) - 1, int(parts.group(3)))
        except ValueError:
            pass
    formats = ['%Y-%m-%d', '%Y/%m/%d', '%d/%m/%Y', '%Y年%m月%d日']
    for fmt in formats:
        try:
            return datetime.strptime(str(date_str), fmt)
        except ValueError:
            continue
    return None

def _get_status(value, thresholds):
    """根据阈值返回 high/medium/normal，thresholds=(high, medium)"""
    high_t, med_t = thresholds
    if value > high_t:
        return 'high'
    elif value > med_t:
        return 'medium'
    return 'normal'

def _has_time_info(date_str):
    """日期字符串里是否明确写了时间（如 '2024-01-05 23:30'）"""
    return bool(re.search(r'\d{1,2}[:：]\d{2}', str(date_str)))

def _parse_time_hour(date_str):
    """提取小时数；调用前应先经 _has_time_info 判断"""
    m = re.search(r'(\d{1,2})[:：]\d{2}', str(date_str))
    return int(m.group(1)) if m else 0

def analyze_risk(data):
    # ---------------- 数据提取与安全校验 ----------------
    patients = data.get('patients') or []
    visits = data.get('visits') or []
    expenses = data.get('expenses') or []
    drug_mismatch = data.get('drug_mismatch') or []
    duplicate_tests = data.get('duplicate_tests') or []
    patient_anomalies = data.get('patient_anomalies') or []
    suspicious_doctors = data.get('suspicious_doctors') or []
    abnormal_hospitals = data.get('abnormal_hospitals') or []

    # ---------------- 数据有效性校验：空数据直接报错，不再误判为高风险 ----------------
    if not patients and not visits and not expenses:
        raise ValueError('数据为空，没有可分析的患者、就诊或费用记录，请检查输入数据')

    total_patients = len(patients)
    total_visits = len(visits)
    total_expenses = 0
    for e in expenses:
        try:
            total_expenses += float(e.get('amount', 0) or 0)
        except (ValueError, TypeError):
            pass
    total_expenses = round(total_expenses, 2)
    avg_expense = round(total_expenses / total_visits) if total_visits > 0 else 0

    # ---------------- 统计项计算 ----------------
    night_visits = 0
    holiday_visits = 0
    unique_hospitals = set()
    patient_visit_counts = defaultdict(int)
    patient_department_counts = defaultdict(int)
    visit_dates_by_patient = defaultdict(list)
    consecutive_day_flags = set()
    same_dept_high_freq = []

    for visit in visits:
        hospital_id = visit.get('hospital_id')
        patient_id = visit.get('patient_id')
        department = visit.get('department', '')
        visit_date = visit.get('visit_date')

        if hospital_id:
            unique_hospitals.add(hospital_id)
        if patient_id:
            patient_visit_counts[patient_id] += 1
            if department:
                patient_department_counts[(patient_id, department)] += 1

        date_obj = parse_date(visit_date) if visit_date else None
        if date_obj:
            if patient_id:
                visit_dates_by_patient[patient_id].append(date_obj)
            # 夜间就诊：仅当日期中明确包含时间时才判定，
            # 只写年月日的记录不再被误判为凌晨就诊
            if _has_time_info(visit_date):
                hour = _parse_time_hour(visit_date)
                if hour >= 22 or hour < 6:
                    night_visits += 1
            weekday = date_obj.weekday()
            if weekday >= 5:  # 周六=5, 周日=6
                holiday_visits += 1

    # 连续两日就诊检测（同患者）
    for pid, dates in visit_dates_by_patient.items():
        if len(dates) >= 2:
            sorted_dates = sorted(dates)
            for i in range(len(sorted_dates) - 1):
                diff = (sorted_dates[i+1] - sorted_dates[i]).days
                if diff <= 1:
                    consecutive_day_flags.add(pid)
                    break

    # 同科室过高频就诊（>5次）
    for (pid, dept), cnt in patient_department_counts.items():
        if cnt > 5:
            same_dept_high_freq.append((pid, dept, cnt))

    # 自付比例均值
    ratios = []
    for e in expenses:
        r = e.get('self_pay_ratio', 0)
        if isinstance(r, (int, float)):
            ratios.append(float(r))
    avg_self_pay_ratio = sum(ratios) / len(ratios) if ratios else 0

    drug_mismatch_count = len(drug_mismatch)
    duplicate_tests_count = len(duplicate_tests)
    patient_anomalies_count = len(patient_anomalies)
    suspicious_doctors_count = len(suspicious_doctors)
    abnormal_hospitals_count = len(abnormal_hospitals)

    # ---------------- Indicators (对比分析表)  ----------------
    indicator_defs = [
        {
            'name': '就诊次数', 'value': total_visits,
            'normal_range': '1-50',
            'status': _get_status(total_visits, (50, 20))
        },
        {
            'name': '平均费用(元)', 'value': avg_expense,
            'normal_range': '100-800',
            'status': _get_status(avg_expense, (2000, 800))
        },
        {
            'name': '自付比例',
            'value': f"{round(avg_self_pay_ratio * 100, 1)}%" if ratios else '无费用数据',
            'normal_range': '15%-30%',
            # 自付比例越低越异常（仅在有费用记录时评估）
            'status': 'normal' if not ratios else ('high' if avg_self_pay_ratio < 0.05 else ('medium' if avg_self_pay_ratio < 0.1 else 'normal'))
        },
        {
            'name': '夜间就诊', 'value': night_visits,
            'normal_range': '0-3',
            'status': _get_status(night_visits, (5, 2))
        },
        {
            'name': '节假日就诊', 'value': holiday_visits,
            'normal_range': '0-2',
            'status': _get_status(holiday_visits, (4, 2))
        },
        {
            'name': '跨院就诊', 'value': len(unique_hospitals),
            'normal_range': '1-2',
            'status': _get_status(len(unique_hospitals), (3, 2))
        },
        {
            'name': '药品不匹配', 'value': drug_mismatch_count,
            'normal_range': '0',
            'status': 'high' if drug_mismatch_count > 0 else 'normal'
        },
        {
            'name': '重复检查', 'value': duplicate_tests_count,
            'normal_range': '0',
            'status': 'high' if duplicate_tests_count > 0 else 'normal'
        },
        {
            'name': '患者异常', 'value': patient_anomalies_count,
            'normal_range': '0',
            'status': 'high' if patient_anomalies_count > 0 else 'normal'
        },
        {
            'name': '可疑医生', 'value': suspicious_doctors_count,
            'normal_range': '0',
            'status': 'high' if suspicious_doctors_count > 0 else 'normal'
        },
        {
            'name': '异常医院', 'value': abnormal_hospitals_count,
            'normal_range': '0',
            'status': 'high' if abnormal_hospitals_count > 0 else 'normal'
        },
    ]
    indicators = []
    for ind in indicator_defs:
        deviation = '+100%' if ind['status'] == 'high' else ('+50%' if ind['status'] == 'medium' else '正常')
        indicators.append({**ind, 'deviation': deviation})

    # ---------------- 风险评分与详细因子 ----------------
    score = 0
    detailed_factors = []
    top_factors = []

    def add_factor(f_type, item, value, s, top_desc=None):
        nonlocal score
        score += s
        detailed_factors.append({'type': f_type, 'item': item, 'value': value, 'score': s})
        if top_desc:
            top_factors.append(top_desc)

    # 1. 夜间就诊
    if night_visits > 0:
        factor_score = min(night_visits * 5, 15)
        add_factor('就诊行为异常', '夜间就诊', f'{night_visits}次', factor_score, f'夜间就诊{night_visits}次')

    # 2. 节假日就诊
    if holiday_visits > 2:
        factor_score = min(holiday_visits * 4, 12)
        add_factor('就诊行为异常', '节假日高频就诊', f'{holiday_visits}次', factor_score, f'节假日就诊{holiday_visits}次')

    # 3. 连续两日就诊（后端新增的特性，前端也同步补齐）
    if consecutive_day_flags:
        pids = list(consecutive_day_flags)
        factor_score = min(len(pids) * 8, 20)
        add_factor('就诊行为异常', '短期频繁就诊', f'{len(pids)}位患者连续就诊', factor_score, f'{len(pids)}位患者连续两日就诊')

    # 4. 同科室重复就诊（后端特性）
    if same_dept_high_freq:
        factor_score = min(len(same_dept_high_freq) * 10, 20)
        sample_desc = ', '.join([f"{p[0]}在{p[1]}{p[2]}次" for p in same_dept_high_freq[:2]])
        add_factor('就诊行为异常', '重复就诊', sample_desc, factor_score, f'{len(same_dept_high_freq)}例同科室重复就诊')

    # 5. 自付比例过低（仅在有费用记录时评估）
    if ratios and avg_self_pay_ratio < 0.05:
        factor_score = 15
        add_factor('费用异常', '自付比例过低', f'{round(avg_self_pay_ratio * 100, 1)}%', factor_score, '自付比例异常')

    # 6. 平均费用过高
    if avg_expense > 2000:
        factor_score = min(avg_expense // 200 * 5, 20)
        add_factor('费用异常', '平均费用过高', f'{avg_expense}元', factor_score, f'平均费用{avg_expense}元')

    # 7. 药品不匹配
    if drug_mismatch_count > 0:
        factor_score = min(drug_mismatch_count * 10, 25)
        add_factor('医学逻辑异常', '药物使用异常', f'{drug_mismatch_count}项不符', factor_score, f'药品不匹配{drug_mismatch_count}项')

    # 8. 重复检查
    if duplicate_tests_count > 0:
        factor_score = min(duplicate_tests_count * 8, 16)
        add_factor('医学逻辑异常', '重复检查', f'{duplicate_tests_count}次', factor_score, f'重复检查{duplicate_tests_count}次')

    # 9. 患者异常
    if patient_anomalies_count > 0:
        factor_score = min(patient_anomalies_count * 12, 24)
        add_factor('患者行为异常', '患者异常行为', f'{patient_anomalies_count}项', factor_score, f'患者异常{patient_anomalies_count}项')

    # 10. 可疑医生
    if suspicious_doctors_count > 0:
        factor_score = min(suspicious_doctors_count * 15, 30)
        add_factor('医生行为异常', '可疑医生', f'{suspicious_doctors_count}人', factor_score, f'可疑医生{suspicious_doctors_count}人')

    # 11. 异常医疗机构
    if abnormal_hospitals_count > 0:
        factor_score = min(abnormal_hospitals_count * 20, 40)
        add_factor('医疗机构异常', '异常医疗机构', f'{abnormal_hospitals_count}家', factor_score, f'异常医疗机构{abnormal_hospitals_count}家')

    # ---------------- 单项预警 Warnings ----------------
    high_indicators = [i for i in indicators if i['status'] == 'high']
    medium_indicators = [i for i in indicators if i['status'] == 'medium']
    warnings = []
    for ind in high_indicators:
        warnings.append({'level': 'danger', 'message': f"{ind['name']}异常：{ind['value']}，正常范围{ind['normal_range']}"})
    for ind in medium_indicators:
        warnings.append({'level': 'warning', 'message': f"{ind['name']}偏高：{ind['value']}，正常范围{ind['normal_range']}"})

    # ---------------- 总分、等级、建议 ----------------
    score = min(int(score), 100)

    if high_indicators or score >= 80:
        risk_level = '高风险'
        risk_level_color = 'red'
        suggestion = '【单项预警触发】存在高风险指标，建议立即移交医保稽查部门'
    elif medium_indicators or score >= 50:
        risk_level = '中风险'
        risk_level_color = 'orange'
        suggestion = '存在中等风险指标，建议加强监控，进行人工复核'
    elif score >= 20:
        risk_level = '低风险'
        risk_level_color = 'yellow'
        suggestion = '建议定期关注，暂无需特殊处理'
    else:
        risk_level = '低异常'
        risk_level_color = 'green'
        suggestion = '数据正常，继续监控'

    return {
        'score': score,
        'risk_level': risk_level,
        'risk_level_color': risk_level_color,
        'suggestion': suggestion,
        'data_summary': {
            'total_patients': total_patients,
            'total_visits': total_visits,
            'total_expenses': total_expenses,
            'avg_expense': avg_expense,
            'night_visits': night_visits,
            'holiday_visits': holiday_visits
        },
        'indicators': indicators,
        'warnings': warnings,
        'top_factors': top_factors[:5],
        'detailed_factors': detailed_factors[:10]
    }

# ============================================
# CORS 支持：允许本地 file:// 打开的 index.html 直接调用 Flask API
# ============================================
@app.after_request
def add_cors_headers(resp):
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return resp

@app.route('/health', methods=['GET'])
def health_check():
    """健康检查：前端用来判断后端是否启动，决定使用哪种分析模式"""
    return jsonify({
        'status': 'ok',
        'service': '医保欺诈风险识别后端',
        'version': '1.0.0-unified'
    })

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST', 'OPTIONS'])
def analyze():
    # 预检请求直接返回
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200

    data = None
    # 模式1：application/json 直接POST数据（前端主要使用方式）
    if request.is_json:
        try:
            data = request.get_json(force=True, silent=False)
        except Exception as e:
            return jsonify({'error': f'JSON解析失败: {str(e)}'}), 400

    # 模式2：multipart/form-data 文件上传
    if data is None and 'file' in request.files:
        file = request.files['file']
        if not file or file.filename == '':
            return jsonify({'error': '请选择文件'}), 400
        if not allowed_file(file.filename):
            return jsonify({'error': '不支持的文件格式，请上传 JSON 文件（文本数据请用前端文本输入）'}), 400
        try:
            content = file.read().decode('utf-8')
            data = json.loads(content)
        except json.JSONDecodeError:
            return jsonify({'error': '文件格式错误，需要有效的JSON格式'}), 400
        except Exception as e:
            return jsonify({'error': f'读取文件失败: {str(e)}'}), 500

    if data is None:
        return jsonify({'error': '未收到数据，请通过 JSON body 或 file 字段提交'}), 400

    if not isinstance(data, dict):
        return jsonify({'error': '数据格式错误：顶层必须是JSON对象'}), 400

    try:
        result = analyze_risk(data)
        return jsonify(result)
    except ValueError as e:
        # 数据本身无效（如空数据），属于客户端输入问题
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'分析失败: {str(e)}'}), 500

@app.route('/sample', methods=['GET'])
def get_sample():
    sample_data = {
        "patients": [
            {"patient_id": "P001", "name": "张三", "age": 45, "gender": "男", "insurance_type": "职工医保"},
            {"patient_id": "P002", "name": "李四", "age": 62, "gender": "女", "insurance_type": "居民医保"},
            {"patient_id": "P003", "name": "王五", "age": 38, "gender": "男", "insurance_type": "职工医保"}
        ],
        "visits": [
            {"visit_id": "V001", "patient_id": "P001", "hospital_id": "H001", "department": "心内科", "visit_date": "2024-01-05", "diagnosis": "高血压"},
            {"visit_id": "V002", "patient_id": "P001", "hospital_id": "H001", "department": "心内科", "visit_date": "2024-01-06", "diagnosis": "高血压"},
            {"visit_id": "V003", "patient_id": "P001", "hospital_id": "H002", "department": "心内科", "visit_date": "2024-01-07", "diagnosis": "高血压"},
            {"visit_id": "V004", "patient_id": "P001", "hospital_id": "H001", "department": "心内科", "visit_date": "2024-01-12", "diagnosis": "高血压"},
            {"visit_id": "V005", "patient_id": "P001", "hospital_id": "H001", "department": "心内科", "visit_date": "2024-01-13", "diagnosis": "高血压"},
            {"visit_id": "V006", "patient_id": "P002", "hospital_id": "H003", "department": "骨科", "visit_date": "2024-01-10", "diagnosis": "腰椎间盘突出"},
            {"visit_id": "V007", "patient_id": "P002", "hospital_id": "H003", "department": "骨科", "visit_date": "2024-01-11", "diagnosis": "腰椎间盘突出"},
            {"visit_id": "V008", "patient_id": "P003", "hospital_id": "H001", "department": "神经内科", "visit_date": "2024-01-08", "diagnosis": "头痛"},
            {"visit_id": "V009", "patient_id": "P003", "hospital_id": "H001", "department": "神经内科", "visit_date": "2024-01-09", "diagnosis": "头痛"},
            {"visit_id": "V010", "patient_id": "P001", "hospital_id": "H001", "department": "心内科", "visit_date": "2024-01-15", "diagnosis": "高血压"},
            {"visit_id": "V011", "patient_id": "P001", "hospital_id": "H001", "department": "心内科", "visit_date": "2024-01-19", "diagnosis": "高血压"},
            {"visit_id": "V012", "patient_id": "P001", "hospital_id": "H001", "department": "心内科", "visit_date": "2024-01-20", "diagnosis": "高血压"},
            {"visit_id": "V013", "patient_id": "P001", "hospital_id": "H001", "department": "心内科", "visit_date": "2024-01-26", "diagnosis": "高血压"},
            {"visit_id": "V014", "patient_id": "P001", "hospital_id": "H001", "department": "心内科", "visit_date": "2024-01-27", "diagnosis": "高血压"},
            {"visit_id": "V015", "patient_id": "P002", "hospital_id": "H003", "department": "骨科", "visit_date": "2024-01-12", "diagnosis": "腰椎间盘突出"}
        ],
        "expenses": [
            {"expense_id": "E001", "visit_id": "V001", "amount": 520, "self_pay_ratio": 0.15, "items": ["药品", "检查"]},
            {"expense_id": "E002", "visit_id": "V002", "amount": 480, "self_pay_ratio": 0.12, "items": ["药品"]},
            {"expense_id": "E003", "visit_id": "V003", "amount": 1850, "self_pay_ratio": 0.02, "items": ["急诊", "药品", "检查"]},
            {"expense_id": "E004", "visit_id": "V004", "amount": 620, "self_pay_ratio": 0.18, "items": ["药品", "检查"]},
            {"expense_id": "E005", "visit_id": "V005", "amount": 550, "self_pay_ratio": 0.14, "items": ["药品"]},
            {"expense_id": "E006", "visit_id": "V006", "amount": 1200, "self_pay_ratio": 0.20, "items": ["检查", "药品"]},
            {"expense_id": "E007", "visit_id": "V007", "amount": 850, "self_pay_ratio": 0.16, "items": ["药品"]},
            {"expense_id": "E008", "visit_id": "V008", "amount": 320, "self_pay_ratio": 0.25, "items": ["检查"]},
            {"expense_id": "E009", "visit_id": "V009", "amount": 320, "self_pay_ratio": 0.25, "items": ["检查"]},
            {"expense_id": "E010", "visit_id": "V010", "amount": 2100, "self_pay_ratio": 0.01, "items": ["急诊", "药品", "检查"]},
            {"expense_id": "E011", "visit_id": "V011", "amount": 580, "self_pay_ratio": 0.15, "items": ["药品", "检查"]},
            {"expense_id": "E012", "visit_id": "V012", "amount": 620, "self_pay_ratio": 0.14, "items": ["药品", "检查"]},
            {"expense_id": "E013", "visit_id": "V013", "amount": 560, "self_pay_ratio": 0.16, "items": ["药品"]},
            {"expense_id": "E014", "visit_id": "V014", "amount": 540, "self_pay_ratio": 0.15, "items": ["药品"]},
            {"expense_id": "E015", "visit_id": "V015", "amount": 980, "self_pay_ratio": 0.18, "items": ["药品"]}
        ],
        "doctors": {
            "D001": {"name": "刘医生", "department": "心内科", "hospital_id": "H001"},
            "D002": {"name": "王医生", "department": "骨科", "hospital_id": "H003"}
        },
        "hospitals": {
            "H001": {"name": "第一人民医院", "level": "三级甲等"},
            "H002": {"name": "第二人民医院", "level": "三级乙等"},
            "H003": {"name": "康复专科医院", "level": "二级"}
        },
        "drug_mismatch": [
            {"patient_id": "P001", "drug": "抗生素", "diagnosis": "高血压", "visit_id": "V003"}
        ],
        "duplicate_tests": [
            {"patient_id": "P003", "test_name": "头部CT", "visit_ids": ["V008", "V009"]}
        ],
        "patient_anomalies": [
            {"patient_id": "P001", "type": "串号就医", "description": "使用多个医保号就诊"}
        ]
    }
    return jsonify(sample_data)

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': '上传文件过大，最大支持 16MB'}), 413

if __name__ == '__main__':
    # 不绑定 0.0.0.0，默认 127.0.0.1 更安全（只允许本机访问）
    # debug=False 避免 Werkzeug reloader 导致端口检查冲突
    app.run(debug=False, host='127.0.0.1', port=5000)