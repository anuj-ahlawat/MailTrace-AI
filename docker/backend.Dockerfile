FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY backend/requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && useradd -u 10001 -m mailtrace
COPY backend /srv/backend
COPY ml /srv/ml
ARG INSTALL_DEEP=false
RUN if [ "$INSTALL_DEEP" = "true" ]; then pip install --no-cache-dir -r /srv/ml/requirements-deep.txt; fi
COPY scripts /srv/scripts
COPY .env.example /srv/.env.example
RUN mkdir -p /srv/data && chown -R mailtrace:mailtrace /srv/data
USER mailtrace
WORKDIR /srv/backend
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
