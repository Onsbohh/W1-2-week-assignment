import {promisePool} from '../../database/db';
import CustomError from '../../classes/CustomError';
import {ResultSetHeader, RowDataPacket} from 'mysql2';
import {User} from '../../types/DBTypes';
import {MessageResponse} from '../../types/MessageTypes';

const getAllUsers = async (): Promise<User[]> => {
  const [rows] = await promisePool.execute<RowDataPacket[] & User[]>(
    `
    SELECT user_id, user_name, email, role 
    FROM sssf_user
    `
  );
  if (rows.length === 0) {
    throw new CustomError('No users found', 404);
  }
  return rows;
};

const getUser = async (userId: number): Promise<User> => {
  const [rows] = await promisePool.execute<RowDataPacket[] & User[]>(
    `
    SELECT user_id, user_name, email, role 
    FROM sssf_user 
    WHERE user_id = ?;
    `,
    [userId]
  );
  if (rows.length === 0) {
    throw new CustomError('No users found', 404);
  }
  return rows[0];
};

const addUser = async (user: User): Promise<MessageResponse> => {
  const sql = await promisePool.format('INSERT INTO sssf_user (user_name, email, password) VALUES (?, ?, ?);',[
    user.user_name,
    user.email,
    user.password
  ]);
  const [headers] = await promisePool.execute<ResultSetHeader>(sql);

  if (headers.affectedRows === 0){
    throw new CustomError("No users added", 400);
  } else {
    return {message: "User added", id: headers.insertId} as MessageResponse;
  }
};


const updateUser = async (
  data: Partial<User>,
  userId: number
): Promise<MessageResponse> => {
  const sql = promisePool.format('UPDATE sssf_user SET ? WHERE user_id = ?;', [
    data,
    userId,
  ]);
  const [headers] = await promisePool.execute<ResultSetHeader>(sql);
  if (headers.affectedRows === 0) {
    throw new CustomError('No users updated', 400);
  }
  return {message: 'User updated'};
};

const deleteUser = async (userId: number): Promise<MessageResponse> => {
  const sql = promisePool.format(
    'DELETE FROM sssf_user WHERE user_id = ?;',
    [userId]
  );
  const [headers] = await promisePool.execute<ResultSetHeader>(sql);
  if (headers.affectedRows === 0) {
    throw new CustomError('No users deleted', 400);
  }
  return {message: 'User deleted'};
};

const getUserLogin = async (email: string): Promise<User> => {
  const [rows] = await promisePool.execute<RowDataPacket[] & User[]>(
    `
    SELECT * FROM sssf_user 
    WHERE email = ?;
    `,
    [email]
  );
  if (rows.length === 0) {
    throw new CustomError('Invalid username/password', 200);
  }
  return rows[0];
};

export {getAllUsers, getUser, addUser, updateUser, deleteUser, getUserLogin};
