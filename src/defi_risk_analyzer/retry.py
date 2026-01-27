"""Simple retry decorator for API calls."""
import time
from functools import wraps
from typing import Callable, TypeVar, ParamSpec


P = ParamSpec("P")
R = TypeVar("R")


def with_retry(
    max_attempts: int = 3,
    delay_seconds: float = 1.0,
    backoff_multiplier: float = 2.0,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Retry decorator for functions that may fail transiently.
    
    Args:
        max_attempts: Maximum number of attempts (default: 3)
        delay_seconds: Initial delay between retries in seconds (default: 1.0)
        backoff_multiplier: Multiplier for exponential backoff (default: 2.0)
    
    Returns:
        Decorated function that will retry on exceptions
    """
    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            delay = delay_seconds
            last_exception: Exception | None = None
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        time.sleep(delay)
                        delay *= backoff_multiplier
            
            # If we exhausted all attempts, raise the last exception
            if last_exception:
                raise last_exception
            raise RuntimeError("Retry logic failed without exception")
        
        return wrapper
    return decorator
