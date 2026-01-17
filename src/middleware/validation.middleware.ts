import Joi from 'joi';
import { Request, Response, NextFunction } from 'express';

const schemas = {
  register: Joi.object({
    email: Joi.string().email().required().messages({
      'string.email': 'El email debe ser válido',
      'any.required': 'El email es requerido',
    }),
    password: Joi.string().min(6).required().messages({
      'string.min': 'La contraseña debe tener al menos 6 caracteres',
      'any.required': 'La contraseña es requerida',
    }),
    name: Joi.string().optional(),
  }),

  login: Joi.object({
    email: Joi.string().email().required().messages({
      'string.email': 'El email debe ser válido',
      'any.required': 'El email es requerido',
    }),
    password: Joi.string().required().messages({
      'any.required': 'La contraseña es requerida',
    }),
  }),

  refresh: Joi.object({
    refreshToken: Joi.string().required().messages({
      'any.required': 'El refresh token es requerido',
    }),
  }),
};

type SchemaName = keyof typeof schemas;

export const validate = (schemaName: SchemaName) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const schema = schemas[schemaName];
    const { error } = schema.validate(req.body, { abortEarly: false });

    if (error) {
      const errors = error.details.map((detail) => detail.message);
      return res.status(400).json({
        success: false,
        message: 'Validación fallida',
        errors,
      });
    }

    next();
  };
};
