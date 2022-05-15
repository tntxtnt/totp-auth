#include "totp.h"
#include <SFML/Graphics.hpp>
#include <utility>
using namespace CryptoPP;

namespace ui
{
sf::Font font;

auto init() -> bool {
    return font.loadFromFile("./res/fonts/RobotoMono-Regular.ttf");
}

class TimeLeftShape : public sf::Shape {
public:
    TimeLeftShape(float radius, size_t maximumPoints = 30, float percentage = 1.0F)
    : radius(radius), percentage(percentage), maximumPoints(maximumPoints) {
        update();
    }
    void setPercentage(float percentage) {
        this->percentage = percentage;
        update();
    }

private:
    auto getPointCount() const -> size_t override {
        return static_cast<size_t>(std::ceil(maximumPoints * percentage)) + 1;
    }
    auto getPoint(size_t index) const -> sf::Vector2f override {
        static const float tau = 6.283185307F;
        if (index == 0) return {radius, radius};
        float angle = --index * tau / maximumPoints - tau / 4;
        float x = -cos(angle) * radius;
        float y = sin(angle) * radius;
        return {radius + x, radius + y};
    }


    float radius;
    float percentage;
    size_t maximumPoints;
};

class Row : public sf::Drawable, public sf::Transformable {
public:
    Row(const std::string& name, std::string base32Key)
    : label(name, font, 10),
      base32Key(std::move(base32Key)),
      code("Invalid key", font, 24),
      timeLeft(5.5F, 100),
      timeLeftPercentage(0),
      background(sf::Vector2f(240, 80)) {
        background.setFillColor(sf::Color::White);
        code.move(20, 15);
        code.setFillColor(sf::Color(0x00, 0x59, 0xcf));
        label.setPosition(code.getPosition() + sf::Vector2f(0, 40));
        label.setFillColor(sf::Color(0x44, 0x44, 0x44));
        timeLeft.move(code.getPosition() + sf::Vector2f(190, 39));
        timeLeft.setFillColor(code.getFillColor());
    }
    void update() {
        float timeLeftPercentage = (float)totp::timeLeft().count() / 30;
        if (timeLeftPercentage > this->timeLeftPercentage) {
            if (auto code = totp::googleAuthenticatorCode(base32Key)) {
                auto codeStr = *code;
                codeStr.insert(3, 1, ' ');
                this->code.setString(codeStr);
            }
        }
        timeLeft.setPercentage(this->timeLeftPercentage = timeLeftPercentage);
    }
    auto getName() const -> std::string { return label.getString().toAnsiString(); }

private:
    void draw(sf::RenderTarget& target, sf::RenderStates states) const override {
        states.transform *= getTransform();

        target.draw(background, states);
        target.draw(label, states);
        target.draw(code, states);
        target.draw(timeLeft, states);
    }


    sf::Text label;
    std::string base32Key;
    mutable sf::Text code;
    mutable TimeLeftShape timeLeft;
    float timeLeftPercentage;
    sf::RectangleShape background;
};

class Rows : public sf::Drawable {
public:
    void append(const std::string& name, const std::string& base32Key) {
        rows.emplace_back(found(name) ? rename(name) : name, base32Key);
        // Move new row to last row position
        if (rows.size() > 1) rows.back().move(end(rows)[-2].getPosition());
        rows.back().move(0, 15.F + (rows.size() > 1 ? 80.F : 0));
    }
    auto size() const -> size_t { return rows.size(); }
    void update() {
        for (auto& row : rows) row.update();
    }

private:
    auto rename(std::string name) const -> std::string {
        name += " (";
        for (int i = 1;; ++i) {
            std::string newName = name + std::to_string(i) + ")";
            if (!found(newName)) return newName;
        }
    }
    auto found(const std::string& name) const -> bool {
        return std::find_if(begin(rows), end(rows), [=](auto& row) { return row.getName() == name; }) != end(rows);
    }
    void draw(sf::RenderTarget& target, sf::RenderStates states) const override {
        for (const auto& row : rows) target.draw(row, states);
    }


    std::vector<ui::Row> rows;
};
} // namespace ui

auto main() -> int {
    if (!ui::init()) return 1;

    sf::ContextSettings ctxSettings;
    ctxSettings.antialiasingLevel = 8;
    sf::RenderWindow window({240, 400}, "TOTP Auth", sf::Style::Titlebar | sf::Style::Close, ctxSettings);
    window.setFramerateLimit(30);

    ui::Rows rows;
    rows.append("test1", "JBSWY3DPEHPK3PXP");
    rows.append("test key: 2222333344445555", "2222 3333 4444 5555");
    rows.append("test hnry", "hnry ijgf 4htg lxat ixls uirh qe3e 3jtx ");

    while (window.isOpen()) {
        for (sf::Event event{}; window.pollEvent(event);) {
            if (event.type == sf::Event::Closed) window.close();
        }

        rows.update();

        window.clear(sf::Color(0xcc, 0xcc, 0xcc));
        window.draw(rows);
        window.display();
    }
}
