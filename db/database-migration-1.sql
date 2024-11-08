
-- Create new tables for specialists and fields in Russian language

-- Table for various fields of expertise in medicine
CREATE TABLE fields (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL -- Название медицинского направления (например, кардиология)
);

-- Table for specialists with references to specific medical fields
CREATE TABLE specialists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, -- Имя специалиста
    field_id INTEGER NOT NULL, -- Ссылка на направление (например, кардиология, неврология)
    experience INTEGER NOT NULL, -- Опыт работы в годах
    FOREIGN KEY (field_id) REFERENCES fields(id)
);

-- Insert sample medical fields (20 fields) in Russian
INSERT INTO fields (name) VALUES 
    ('Кардиология'), ('Неврология'), ('Дерматология'), ('Педиатрия'), 
    ('Ортопедия'), ('Психиатрия'), ('Онкология'), ('Офтальмология'), 
    ('Радиология'), ('Эндокринология'), ('Гастроэнтерология'), 
    ('Гематология'), ('Пульмонология'), ('Урология'), ('Нефрология'), 
    ('Аллергология'), ('Инфекционные заболевания'), ('Терапия'), 
    ('Хирургия'), ('Реабилитация');

-- Insert 30 specialist records in Russian
INSERT INTO specialists (name, field_id, experience) VALUES 
    ('Иван Иванов', 1, 10), ('Анна Смирнова', 2, 12), ('Олег Кузнецов', 3, 8), 
    ('Елена Попова', 4, 15), ('Дмитрий Соколов', 5, 9), ('Мария Козлова', 6, 11), 
    ('Наталья Морозова', 7, 13), ('Александр Васильев', 8, 7), 
    ('Ольга Петрова', 9, 5), ('Павел Николаев', 10, 6), ('Светлана Михайлова', 11, 4), 
    ('Константин Григорьев', 12, 20), ('Сергей Лебедев', 13, 17), 
    ('Андрей Новиков', 14, 10), ('Юлия Фролова', 15, 9), ('Николай Пахомов', 16, 3), 
    ('Ирина Волкова', 17, 12), ('Оксана Зайцева', 18, 5), ('Виктор Павлов', 19, 14), 
    ('Екатерина Соловьева', 20, 6), ('Алексей Чернов', 1, 19), 
    ('Людмила Федорова', 2, 18), ('Артем Малышев', 3, 11), 
    ('Валентина Куликова', 4, 7), ('Петр Лазарев', 5, 13), ('София Мельникова', 6, 10), 
    ('Иван Голубев', 7, 16), ('Ольга Симонова', 8, 9), 
    ('Максим Петров', 9, 8), ('Елена Гаврилова', 10, 4);

-- Additional sample assignments (10 records)
INSERT INTO assigned_doctors (client_id, doctor_id, assigned_date) VALUES
    (1, 1, '2024-01-01'), (2, 1, '2024-01-05'), (3, 2, '2024-01-07'), 
    (4, 2, '2024-01-09'), (5, 3, '2024-01-15'), (6, 3, '2024-02-01'), 
    (7, 4, '2024-02-03'), (8, 4, '2024-02-05'), (9, 5, '2024-02-10'), 
    (10, 5, '2024-02-15');

-- Sample prescriptions (10 records)
INSERT INTO prescriptions (client_id, doctor_id, prescription, date) VALUES
    (1, 1, 'Лекарство A по 1 таблетке утром', '2024-03-01'), 
    (2, 1, 'Лекарство B по 2 таблетки вечером', '2024-03-02'), 
    (3, 2, 'Мазь X наносить 2 раза в день', '2024-03-03'), 
    (4, 2, 'Сироп Y по 5 мл перед сном', '2024-03-05'), 
    (5, 3, 'Капли Z в оба глаза 3 раза в день', '2024-03-07'), 
    (6, 3, 'Порошок L развести в воде и выпить', '2024-03-10'), 
    (7, 4, 'Таблетки Q по 1 таблетке утром и вечером', '2024-03-12'), 
    (8, 4, 'Спрей R наносить на рану 2 раза в день', '2024-03-15'), 
    (9, 5, 'Сироп M по 10 мл до еды', '2024-03-18'), 
    (10, 5, 'Таблетки S по 1 таблетке каждые 8 часов', '2024-03-20');
