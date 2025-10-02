package com.senai.eventsmanager.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class TemAnoRomanos implements ConstraintValidator<DeveTerAnoRomanos, String>{
    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        return value.contains("MCMXII");
}
}
