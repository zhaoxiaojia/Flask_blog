"""empty message

Revision ID: 9852a5ea3cb8
Revises: 1c5761d6fc90
Create Date: 2020-08-19 08:10:13.685715

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9852a5ea3cb8'
down_revision = '1c5761d6fc90'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('roles', sa.Column('default', sa.Boolean(), nullable=True))
    op.add_column('roles', sa.Column('permission', sa.Integer(), nullable=True))
    op.create_index(op.f('ix_roles_default'), 'roles', ['default'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_roles_default'), table_name='roles')
    op.drop_column('roles', 'permission')
    op.drop_column('roles', 'default')
    # ### end Alembic commands ###
