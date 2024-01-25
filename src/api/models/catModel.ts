import {promisePool} from '../../database/db';
import CustomError from '../../classes/CustomError';
import {ResultSetHeader, RowDataPacket} from 'mysql2';
import {Cat, User} from '../../types/DBTypes';
import {MessageResponse, UploadResponse} from '../../types/MessageTypes';
import UserRoute from '../routes/userRoute';

const getAllCats = async (): Promise<Cat[]> => {
  const [rows] = await promisePool.execute<RowDataPacket[] & Cat[]>(
    `
    SELECT cat_id, cat_name, weight, filename, birthdate, ST_X(coords) as lat, ST_Y(coords) as lng,
    JSON_OBJECT('user_id', sssf_user.user_id, 'user_name', sssf_user.user_name) AS owner 
	  FROM sssf_cat 
	  JOIN sssf_user 
    ON sssf_cat.owner = sssf_user.user_id
    `
  );
  if (rows.length === 0) {
    throw new CustomError('No cats found', 404);
  }
  const cats = (rows as Cat[]).map((row) => ({
    ...row,
    owner: JSON.parse(row.owner?.toString() || '{}'),
  }));

  return cats;
};

const getCat = async (catId: number): Promise<Cat> => {
  const [rows] = await promisePool.execute<RowDataPacket[] & Cat[]>(
    `
    SELECT cat_id, cat_name, weight, filename, birthdate, ST_X(coords) as lat, ST_Y(coords) as lng,
    JSON_OBJECT('user_id', sssf_user.user_id, 'user_name', sssf_user.user_name) AS owner
    FROM sssf_cat
    JOIN sssf_user
    ON sssf_cat.owner = sssf_user.user_id
    WHERE cat_id = ?;
    `,
    [catId]
  );
  if (rows.length === 0) {
    throw new CustomError("No cat found", 400);
  }
  const cats = (rows as Cat[]).map((row) => ({
    ...row,
    owner: JSON.parse(row.owner?.toString() || '{}'),
  }));
  return cats[0];
};

const addCat = async (data: Cat): Promise<MessageResponse> => {
  const [headers] = await promisePool.execute<ResultSetHeader>(
    `
    INSERT INTO sssf_cat (cat_name, weight, owner, filename, birthdate, coords) 
    VALUES (?, ?, ?, ?, ?, POINT(?, ?))
    `,
    [
      data.cat_name,
      data.weight,
      data.owner,
      data.filename,
      data.birthdate,
      data.lat,
      data.lng,
    ]
  );
  if (headers.affectedRows === 0) {
    throw new CustomError('No cats added', 400);
  }
  data.cat_id = headers.insertId;
  return {message: 'Cat added' + data.cat_id, id: data.cat_id} as MessageResponse;
};

const updateCat = async (
  data: Partial<Cat>,
  catId: number
): Promise<MessageResponse> => {
  const sql = promisePool.format('UPDATE sssf_cat SET ? WHERE cat_id = ?;', [
    data,
    catId,
    ]);

    const [headers] = await promisePool.execute<ResultSetHeader>(sql);

    if (headers.affectedRows === 0) {
      throw new CustomError('No cats updated', 400);
    }
    return {message: 'Cat updated'}; 
};

const deleteCat = async (catId: number): Promise<MessageResponse> => {
  const [headers] = await promisePool.execute<ResultSetHeader>(
    `
    DELETE FROM sssf_cat 
    WHERE cat_id = ?;
    `,
    [catId]
  );
  if (headers.affectedRows === 0) {
    throw new CustomError('No cats deleted', 400);
  }
  return {message: 'Cat deleted'};
};

export {getAllCats, getCat, addCat, updateCat, deleteCat};
