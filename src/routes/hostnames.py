from flask import Blueprint, jsonify, request
from src.models.user import db
from src.models.hostnames import HnCategory, HnApp, HnRule, bootstrap_defaults

hostnames_bp = Blueprint('hostnames_bp', __name__, url_prefix='/api/hostnames')


@hostnames_bp.route('/bootstrap', methods=['POST'])
def hostnames_bootstrap():
    print('hostnames_bootstrap()')
    bootstrap_defaults()
    return jsonify({'status': 'ok'})


# Categories
@hostnames_bp.route('/categories', methods=['GET'])
def list_categories():
    print('list_categories()')
    items = [c.to_dict() for c in HnCategory.query.order_by(HnCategory.name).all()]
    return jsonify({'categories': items})


@hostnames_bp.route('/categories', methods=['POST'])
def create_category():
    data = request.get_json(force=True)
    print('create_category()', data)
    item = HnCategory(name=data['name'], description=data.get('description'))
    db.session.add(item)
    db.session.commit()
    return jsonify(item.to_dict()), 201


@hostnames_bp.route('/categories/<int:cat_id>', methods=['PUT'])
def update_category(cat_id):
    data = request.get_json(force=True)
    print('update_category()', cat_id, data)
    item = HnCategory.query.get_or_404(cat_id)
    item.name = data.get('name', item.name)
    item.description = data.get('description', item.description)
    db.session.commit()
    return jsonify(item.to_dict())


@hostnames_bp.route('/categories/<int:cat_id>', methods=['DELETE'])
def delete_category(cat_id):
    print('delete_category()', cat_id)
    item = HnCategory.query.get_or_404(cat_id)
    db.session.delete(item)
    db.session.commit()
    return jsonify({'status': 'deleted'})


# Apps
@hostnames_bp.route('/apps', methods=['GET'])
def list_apps():
    cat_id = request.args.get('category_id', type=int)
    print('list_apps()', {'category_id': cat_id})
    q = HnApp.query
    if cat_id:
        q = q.filter_by(category_id=cat_id)
    items = [a.to_dict() for a in q.order_by(HnApp.name).all()]
    return jsonify({'apps': items})


@hostnames_bp.route('/apps', methods=['POST'])
def create_app():
    data = request.get_json(force=True)
    print('create_app()', data)
    item = HnApp(category_id=data['category_id'], name=data['name'], slug=data.get('slug'))
    db.session.add(item)
    db.session.commit()
    return jsonify(item.to_dict()), 201


@hostnames_bp.route('/apps/<int:app_id>', methods=['PUT'])
def update_app(app_id):
    data = request.get_json(force=True)
    print('update_app()', app_id, data)
    item = HnApp.query.get_or_404(app_id)
    item.name = data.get('name', item.name)
    item.slug = data.get('slug', item.slug)
    if 'category_id' in data:
        item.category_id = data['category_id']
    db.session.commit()
    return jsonify(item.to_dict())


@hostnames_bp.route('/apps/<int:app_id>', methods=['DELETE'])
def delete_app(app_id):
    print('delete_app()', app_id)
    item = HnApp.query.get_or_404(app_id)
    db.session.delete(item)
    db.session.commit()
    return jsonify({'status': 'deleted'})


# Rules
@hostnames_bp.route('/rules', methods=['GET'])
def list_rules():
    app_id = request.args.get('app_id', type=int)
    print('list_rules()', {'app_id': app_id})
    q = HnRule.query
    if app_id:
        q = q.filter_by(app_id=app_id)
    items = [r.to_dict() for r in q.order_by(HnRule.created_at.desc()).all()]
    return jsonify({'rules': items})


@hostnames_bp.route('/rules', methods=['POST'])
def create_rule():
    data = request.get_json(force=True)
    print('create_rule()', data)
    item = HnRule(app_id=data['app_id'], type=data['type'], value=data['value'], source=data.get('source', 'manual'), confidence=float(data.get('confidence', 1.0)))
    db.session.add(item)
    db.session.commit()
    return jsonify(item.to_dict()), 201


@hostnames_bp.route('/rules/<int:rule_id>', methods=['PUT'])
def update_rule(rule_id):
    data = request.get_json(force=True)
    print('update_rule()', rule_id, data)
    item = HnRule.query.get_or_404(rule_id)
    item.type = data.get('type', item.type)
    item.value = data.get('value', item.value)
    item.source = data.get('source', item.source)
    if 'confidence' in data:
        item.confidence = float(data['confidence'])
    if 'app_id' in data:
        item.app_id = data['app_id']
    db.session.commit()
    return jsonify(item.to_dict())


@hostnames_bp.route('/rules/<int:rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    print('delete_rule()', rule_id)
    item = HnRule.query.get_or_404(rule_id)
    db.session.delete(item)
    db.session.commit()
    return jsonify({'status': 'deleted'})


