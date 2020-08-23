"""empty message

Revision ID: 3eb110989b79
Revises: 6461199b3049
Create Date: 2020-08-20 07:25:13.997254

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3eb110989b79'
down_revision = '6461199b3049'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('avator_hash', sa.String(length=32), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'avator_hash')
    # ### end Alembic commands ###