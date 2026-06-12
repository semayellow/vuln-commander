import re
from pathlib import Path
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.dialects import postgresql


revision: str = '5db404bd006e'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_VIEW_NAME_RE = re.compile(
    r'CREATE\s+OR\s+REPLACE\s+VIEW\s+(\w+)',
    re.IGNORECASE | re.MULTILINE,
)


def _load_views_sql() -> str:
    """Resolve sql_queries: Docker copies it next to migrations"""
    here = Path(__file__).resolve()
    queries_path = here.parents[1] / 'views_generation_spec'
    return queries_path.read_text(encoding='utf-8')


def _split_sql_statements(sql: str) -> list[str]:
    sql = sql.replace('\r\n', '\n').strip()
    if not sql:
        return []
    statements: list[str] = []
    chunk: list[str] = []
    for line in sql.split('\n'):
        stripped = line.strip()
        if not chunk and not stripped:
            continue
        chunk.append(line)
        if line.rstrip().endswith(';'):
            stmt = '\n'.join(chunk).strip()
            if stmt:
                statements.append(stmt)
            chunk = []
    rest = '\n'.join(chunk).strip()
    if rest:
        statements.append(rest)
    return statements


def upgrade() -> None:
    bind = op.get_bind()

    postgresql.ENUM('ti', 'sandbox', name='userteam').create(bind)
    postgresql.ENUM('active', 'archived', name='projectstatus').create(bind)
    postgresql.ENUM('user', 'admin', name='userrole').create(bind)
    postgresql.ENUM('service', 'devsecops', name='connectorscope').create(bind)
    postgresql.ENUM(
        'iac', 'gss', 'sca_license', 'sca_vuln', 'github', name='connectortype'
    ).create(bind)
    postgresql.ENUM('success', 'failure', name='connectorlastrunstatus').create(bind)
    postgresql.ENUM(
        'info', 'low', 'medium', 'high', 'critical', name='vulnseverity'
    ).create(bind)
    postgresql.ENUM(
        'new',
        'awaiting_review',
        'closed',
        'false_positive',
        'reopened',
        name='vulnstatus',
    ).create(bind)

    userteam = postgresql.ENUM('ti', 'sandbox', name='userteam', create_type=False)
    projectstatus = postgresql.ENUM(
        'active', 'archived', name='projectstatus', create_type=False
    )
    userrole = postgresql.ENUM('user', 'admin', name='userrole', create_type=False)
    connectorscope = postgresql.ENUM(
        'service', 'devsecops', name='connectorscope', create_type=False
    )
    connectortype = postgresql.ENUM(
        'iac',
        'gss',
        'sca_license',
        'sca_vuln',
        'github',
        name='connectortype',
        create_type=False,
    )
    connectorlastrunstatus = postgresql.ENUM(
        'success', 'failure', name='connectorlastrunstatus', create_type=False
    )
    vulnseverity = postgresql.ENUM(
        'info',
        'low',
        'medium',
        'high',
        'critical',
        name='vulnseverity',
        create_type=False,
    )
    vulnstatus = postgresql.ENUM(
        'new',
        'awaiting_review',
        'closed',
        'false_positive',
        'reopened',
        name='vulnstatus',
        create_type=False,
    )

    op.create_table(
        'vc_project',
        sa.Column(
            'id',
            sa.UUID(),
            server_default=sa.text('gen_random_uuid()'),
            nullable=False,
        ),
        sa.Column('team', userteam, nullable=False),
        sa.Column('name', sa.String(), nullable=True),
        sa.Column('default_branch', sa.String(), nullable=False),
        sa.Column('status', projectstatus, nullable=False),
        sa.Column('clone_url', sa.String(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )
    op.create_table(
        'vc_user',
        sa.Column(
            'id',
            sa.UUID(),
            server_default=sa.text('gen_random_uuid()'),
            nullable=False,
        ),
        sa.Column(
            'created_at',
            sa.DateTime(),
            server_default=sa.text("TIMEZONE('utc', now())"),
            nullable=False,
        ),
        sa.Column(
            'updated_at',
            sa.DateTime(),
            server_default=sa.text("TIMEZONE('utc', now())"),
            nullable=False,
        ),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('first_name', sa.String(), nullable=False),
        sa.Column('last_name', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('password', sa.LargeBinary(), nullable=False),
        sa.Column('role', userrole, nullable=False),
        sa.Column('team', userteam, nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
    )
    op.create_table(
        'vc_connector',
        sa.Column(
            'id',
            sa.UUID(),
            server_default=sa.text('gen_random_uuid()'),
            nullable=False,
        ),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('password', sa.LargeBinary(), nullable=False),
        sa.Column('scope', connectorscope, nullable=False),
        sa.Column('type', connectortype, nullable=False),
        sa.Column(
            'created_at',
            sa.DateTime(),
            server_default=sa.text("TIMEZONE('utc', now())"),
            nullable=False,
        ),
        sa.Column(
            'updated_at',
            sa.DateTime(),
            server_default=sa.text("TIMEZONE('utc', now())"),
            nullable=False,
        ),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('is_running', sa.Boolean(), nullable=False),
        sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_run_status', connectorlastrunstatus, nullable=True),
        sa.Column('debug', sa.String(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )
    op.create_table(
        'vc_commit',
        sa.Column(
            'id',
            sa.UUID(),
            server_default=sa.text('gen_random_uuid()'),
            nullable=False,
        ),
        sa.Column('project_id', sa.UUID(), nullable=False),
        sa.Column('author', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('hash', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['vc_project.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'vc_refresh_token',
        sa.Column(
            'id',
            sa.UUID(),
            server_default=sa.text('gen_random_uuid()'),
            nullable=False,
        ),
        sa.Column('user_id', sa.UUID(), nullable=True),
        sa.Column('connector_id', sa.UUID(), nullable=True),
        sa.Column('value', sa.String(), nullable=False),
        sa.Column('expired_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['connector_id'], ['vc_connector.id']),
        sa.ForeignKeyConstraint(['user_id'], ['vc_user.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'vc_connector_scan_history',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('project_id', sa.UUID(), nullable=False),
        sa.Column('connector_type', connectortype, nullable=False),
        sa.Column('scanned_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_commit_hash', sa.String(), nullable=False),
        sa.Column('info', sa.Integer(), nullable=True),
        sa.Column('low', sa.Integer(), nullable=True),
        sa.Column('medium', sa.Integer(), nullable=True),
        sa.Column('high', sa.Integer(), nullable=True),
        sa.Column('critical', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['vc_project.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'vc_vuln',
        sa.Column(
            'id',
            sa.UUID(),
            server_default=sa.text('gen_random_uuid()'),
            nullable=False,
        ),
        sa.Column('project_id', sa.UUID(), nullable=False),
        sa.Column('hash', sa.String(), nullable=False),
        sa.Column('last_commit_hash', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('connector_type', connectortype, nullable=False),
        sa.Column('severity', vulnseverity, nullable=False),
        sa.Column('status', vulnstatus, nullable=False),
        sa.Column('filepath', sa.String(), nullable=False),
        sa.Column('line', sa.String(), nullable=False),
        sa.Column('code_snippet', sa.String(), nullable=False),
        sa.Column('custom_fields', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['vc_project.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('hash'),
    )

    raw_views = _load_views_sql()
    conn = op.get_bind()
    for statement in _split_sql_statements(raw_views):
        conn.execute(text(statement))


def downgrade() -> None:
    raw_views = _load_views_sql()
    view_names = _VIEW_NAME_RE.findall(raw_views)
    conn = op.get_bind()
    for name in reversed(view_names):
        conn.execute(text(f'DROP VIEW IF EXISTS {name}'))

    op.drop_table('vc_vuln')
    op.drop_table('vc_connector_scan_history')
    op.drop_table('vc_refresh_token')
    op.drop_table('vc_commit')
    op.drop_table('vc_connector')
    op.drop_table('vc_user')
    op.drop_table('vc_project')

    postgresql.ENUM(name='vulnstatus').drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name='vulnseverity').drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name='connectorlastrunstatus').drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name='connectortype').drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name='connectorscope').drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name='userrole').drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name='projectstatus').drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name='userteam').drop(op.get_bind(), checkfirst=True)
