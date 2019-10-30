"""add note titimestamp

Revision ID: 9d43256cd1b5
Revises: 
Create Date: 2019-08-11 21:23:19.312959

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '9d43256cd1b5'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('posts', 'state',
               existing_type=mysql.TINYINT(display_width=1),
               nullable=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('posts', 'state',
               existing_type=mysql.TINYINT(display_width=1),
               nullable=True)
    # ### end Alembic commands ###