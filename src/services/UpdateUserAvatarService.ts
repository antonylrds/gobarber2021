import path from 'path';
import fs from 'fs';
import { getRepository } from 'typeorm';

import AppError from '../errors/AppError';

import uploadConfig from '../config/upload';
import User from '../models/User';

interface RequestDTO {
  user_id: string;
  avatarFilename: string;
}

class UpdateUserAvatarService {
  public async execute({ user_id, avatarFilename }: RequestDTO): Promise<User> {
    const usersRepository = getRepository(User);

    const user = await usersRepository.findOne({
      where: {
        id: user_id,
      },
    });

    if (!user) {
      throw new AppError('Only authenticated users can alter avatar', 401);
    }

    if (user.avatar) {
      const userAvatarFilePath = path.join(uploadConfig.directory, user.avatar);
      const userAvatarFileExists = await fs.promises.stat(userAvatarFilePath);

      if (userAvatarFileExists) {
        await fs.promises.unlink(userAvatarFilePath);
      }
    }

    user.avatar = avatarFilename;

    await usersRepository.save(user);

    return user;
  }
}

export default UpdateUserAvatarService;
