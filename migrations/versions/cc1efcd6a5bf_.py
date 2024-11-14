from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'cc1efcd6a5bf'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Drop the foreign key constraint before dropping the 'user' table
    with op.batch_alter_table('content', schema=None) as batch_op:
        batch_op.drop_constraint('content_user_id_fkey', type_='foreignkey')

    # Drop the 'user' table
    op.drop_table('user')

    # Create the new 'users' table
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=120), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('password', sa.String(length=200), nullable=False),
    sa.Column('role', sa.String(length=50), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('username')
    )

    # Recreate the foreign key constraint referencing the 'users' table
    with op.batch_alter_table('content', schema=None) as batch_op:
        batch_op.create_foreign_key('content_user_id_fkey', 'users', ['user_id'], ['id'])


def downgrade():
    # Drop the foreign key constraint before dropping the 'users' table
    with op.batch_alter_table('content', schema=None) as batch_op:
        batch_op.drop_constraint('content_user_id_fkey', type_='foreignkey')

    # Drop the 'users' table
    op.drop_table('users')

    # Recreate the old 'user' table
    op.create_table('user',
    sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('username', sa.VARCHAR(length=120), autoincrement=False, nullable=False),
    sa.Column('email', sa.VARCHAR(length=120), autoincrement=False, nullable=False),
    sa.Column('password', sa.VARCHAR(length=200), autoincrement=False, nullable=False),
    sa.Column('role', sa.VARCHAR(length=50), autoincrement=False, nullable=False),
    sa.PrimaryKeyConstraint('id', name='user_pkey'),
    sa.UniqueConstraint('email', name='user_email_key'),
    sa.UniqueConstraint('username', name='user_username_key')
    )

    # Recreate the foreign key constraint referencing the 'user' table
    with op.batch_alter_table('content', schema=None) as batch_op:
        batch_op.create_foreign_key('content_user_id_fkey', 'user', ['user_id'], ['id'])
