import {
  addCat,
  deleteCat,
  getAllCats,
  getCat,
  updateCat,
} from '../models/catModel';
import {Request, Response, NextFunction} from 'express';
import CustomError from '../../classes/CustomError';
import {validationResult} from 'express-validator';
import {MessageResponse} from '../../types/MessageTypes';
import {Cat, User} from '../../types/DBTypes';

const catListGet = async (
  _req: Request,
  res: Response<Cat[]>,
  next: NextFunction
) => {
  try {
    const cats = await getAllCats();
    res.json(cats);
  } catch (error) {
    next(error);
  }
};

const catGet = async (req: Request, res: Response<Cat>, next: NextFunction) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const messages: string = errors
      .array()
      .map((error) => `${error.msg}: ${error.param}`)
      .join(', ');
    console.log('cat_post validation', messages);
    next(new CustomError(messages, 400));
    return;
  }

  try {
    const id = Number(req.params.id);
    const cat = await getCat(id);
    res.json(cat);
  } catch (error) {
    next(error);
  }
};

const catPost = async (
  req: Request<{}, {}, Omit<Cat, 'owner'> & {owner: number}>,
  res: Response<MessageResponse, {coords: [number, number]}>,
  next: NextFunction
) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const messages: string = errors
      .array()
      .map((error) => `${error.msg}: ${error.param}`)
      .join(', ');
    console.log('cat_post validation', messages);
    next(new CustomError(messages, 400));
    return;
  }
  try {
    if (!req.file) {
      throw new CustomError('File is missing', 400);
    }
    const filename = req.file.filename;
    const [lat, lng] = res.locals.coords;
    const {user_id, role} = req.user as User;

    const cat: Omit<Cat, 'owner'> & {
      owner: number;
      filename: string;
      lat: number;
      lng: number;
      user_id: number;
      role: string;
      cat_id: number;
    } = {
      ...req.body,
      owner: user_id,
      filename,
      lat,
      lng,
      user_id,
      role,
      cat_id: req.body.cat_id,
    };
    console.log('catPost', cat);
    const result = await addCat(cat);
    res.json(result);
  } catch (error) {
    next(error);
  }
};

const catPut = async (
  req: Request<{id: string}, {}, Cat>,
  res: Response<MessageResponse>,
  next: NextFunction
) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const messages: string = errors
      .array()
      .map((error) => `${error.msg}: ${error.param}`)
      .join(', ');
    console.log('cat_put validation', messages);
    next(new CustomError(messages, 400));
    return;
  }
  try {
    const id = Number(req.params.id);
    const cat = req.body;
    const result = await updateCat(cat, id);
    res.json(result);
  } catch (error) {
    next(error);
  }
};

const catDelete = async (
  req: Request<{id: string}>,
  res: Response<MessageResponse>,
  next: NextFunction
) =>{
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const messages: string = errors
      .array()
      .map((error) => `${error.msg}: ${error.param}`)
      .join(', ');
    console.log('cat_delete validation', messages);
    next(new CustomError(messages, 400));
    return;
  }
  try {
    const catId = Number(req.params.id);
    await deleteCat(catId);
    res.json({message: 'Cat deleted'});
  } catch (error) {
    next(error);
  }
};

export {catListGet, catGet, catPost, catPut, catDelete};
