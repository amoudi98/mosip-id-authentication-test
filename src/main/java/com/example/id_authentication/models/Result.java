package com.example.id_authentication.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
public class Result<T> {
    private final boolean isSuccess;
    private final boolean isFailure;
    private final List<Error> errors;
    private final T data;

    private Result(boolean isSuccess, T data, List<Error> errors) {
        this.isSuccess = isSuccess;
        this.isFailure = !isSuccess;
        this.data = data;
        this.errors = errors;
    }

    public static <T> Result<T> success(T data) {
        return new Result<>(true, data, null);
    }

    public static <T> Result<T> failure(List<Error> errors) {
        return new Result<>(false, null, errors);
    }
}